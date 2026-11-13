#include "replay.hpp"

bool ReplayWindow::accept(std::uint64_t seq) {
    auto bit = [this](std::uint64_t s) -> std::uint64_t& { return m_bits[(s / WORD_BITS) % m_bits.size()]; };
    auto mask = [](std::uint64_t s) { return std::uint64_t{1} << (s % WORD_BITS); };

    if (m_empty) {
        m_empty = false;
        m_top = seq;
        bit(seq) |= mask(seq);
        return true;
    }
    if (seq > m_top) {
        // номера между старой и новой вершиной ещё не приходили: их биты остались от номеров на SIZE раньше
        if (seq - m_top >= SIZE) {
            m_bits.fill(0);
        } else {
            for (std::uint64_t s = m_top + 1; s < seq; ++s) bit(s) &= ~mask(s);
            bit(seq) &= ~mask(seq);
        }
        m_top = seq;
        bit(seq) |= mask(seq);
        return true;
    }
    if (m_top - seq >= SIZE) return false;
    if (bit(seq) & mask(seq)) return false;
    bit(seq) |= mask(seq);
    return true;
}

void ReplayWindow::reset() {
    m_bits.fill(0);
    m_top = 0;
    m_empty = true;
}

std::int64_t wall_clock_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

PeerState::Verdict PeerState::check(const PacketHeader& header, std::optional<std::int64_t> keep_alive_time_ns, std::int64_t now_ns) {
    if (m_has_session && header.session == m_session) {
        return m_window.accept(header.seq) ? Verdict::ACCEPT : Verdict::REPLAY;
    }
    if (!keep_alive_time_ns) return Verdict::UNKNOWN_SESSION;

    // разность в беззнаковом виде: время из пакета может быть любым, переполнение int64 - UB
    auto diff = static_cast<std::uint64_t>(*keep_alive_time_ns) - static_cast<std::uint64_t>(now_ns);
    auto skew = static_cast<std::uint64_t>(std::chrono::nanoseconds(MAX_CLOCK_SKEW).count());
    if (diff > skew && -diff > skew) return Verdict::CLOCK_SKEW;
    if (m_has_session && header.session.start_ns <= m_session.start_ns) return Verdict::STALE_SESSION;

    m_session = header.session;
    m_has_session = true;
    m_window.reset();
    m_window.accept(header.seq);
    return Verdict::NEW_SESSION;
}

const char* verdict_name(PeerState::Verdict v) {
    switch (v) {
        case PeerState::Verdict::ACCEPT:
            return "принят";
        case PeerState::Verdict::NEW_SESSION:
            return "новая сессия";
        case PeerState::Verdict::REPLAY:
            return "повтор";
        case PeerState::Verdict::UNKNOWN_SESSION:
            return "неизвестная сессия";
        case PeerState::Verdict::STALE_SESSION:
            return "старая сессия";
        case PeerState::Verdict::CLOCK_SKEW:
            return "расхождение часов";
    }
    return "?";
}
