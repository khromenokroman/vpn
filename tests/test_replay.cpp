#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>

#include "share/replay.hpp"

namespace {

using Verdict = PeerState::Verdict;

constexpr std::int64_t SEC = 1'000'000'000;
/** @brief «Сейчас» в тестах: 2026-11-13. */
constexpr std::int64_t NOW = 1'763'060'000 * SEC;

PacketHeader hdr(std::uint64_t start_ns, std::uint64_t seq, std::uint64_t random = 7) { return {{start_ns, random}, seq}; }

std::string name(Verdict v) { return verdict_name(v); }

} // namespace

/**
 * @brief Номера по порядку принимаются, повтор любого из них отбрасывается.
 */
TEST(ReplayWindow, InOrderAndDuplicates) {
    ReplayWindow w;
    for (std::uint64_t s = 0; s < 5000; ++s) ASSERT_TRUE(w.accept(s)) << "новый номер " << s;
    for (std::uint64_t s : {4999u, 4000u, 2952u}) EXPECT_FALSE(w.accept(s)) << "повтор номера " << s << " (вершина 4999)";
}

/**
 * @brief Номера не по порядку в пределах окна принимаются по одному разу, старше окна - нет.
 */
TEST(ReplayWindow, ReorderInsideWindow) {
    ReplayWindow w;
    ASSERT_TRUE(w.accept(10000));
    EXPECT_TRUE(w.accept(10000 - ReplayWindow::SIZE + 1)) << "самый старый номер окна";
    EXPECT_FALSE(w.accept(10000 - ReplayWindow::SIZE + 1)) << "его повтор";
    EXPECT_FALSE(w.accept(10000 - ReplayWindow::SIZE)) << "на 1 старше окна: не отличить от повтора";
    EXPECT_TRUE(w.accept(9999));
    EXPECT_TRUE(w.accept(9000));
    EXPECT_FALSE(w.accept(9000)) << "повтор пропущенного ранее номера";
}

/**
 * @brief При скачке вершины биты номеров, ещё не приходивших в новом окне, сбрасываются:
 * иначе номер, совпавший по модулю SIZE с давно принятым, сочли бы повтором.
 */
TEST(ReplayWindow, JumpClearsSkippedNumbers) {
    ReplayWindow w;
    for (std::uint64_t s = 0; s < 100; ++s) ASSERT_TRUE(w.accept(s));
    ASSERT_TRUE(w.accept(ReplayWindow::SIZE + 50)) << "скачок вперёд меньше чем на окно";
    for (std::uint64_t s = ReplayWindow::SIZE; s < ReplayWindow::SIZE + 50; ++s) {
        EXPECT_TRUE(w.accept(s)) << "номер " << s << " не приходил; тот же бит раньше занимал номер " << s - ReplayWindow::SIZE;
    }
    ASSERT_TRUE(w.accept(10 * ReplayWindow::SIZE + 3)) << "скачок больше окна";
    EXPECT_TRUE(w.accept(9 * ReplayWindow::SIZE + 50)) << "номер внутри нового окна, не приходил";
    EXPECT_FALSE(w.accept(ReplayWindow::SIZE + 50)) << "номер далеко за окном";
}

/**
 * @brief Окно работает у верхней границы uint64: переполнения при сравнении нет.
 */
TEST(ReplayWindow, NearMaxSeq) {
    ReplayWindow w;
    constexpr std::uint64_t MAX = UINT64_MAX;
    ASSERT_TRUE(w.accept(MAX - 1));
    EXPECT_TRUE(w.accept(MAX));
    EXPECT_FALSE(w.accept(MAX));
    EXPECT_FALSE(w.accept(0)) << "0 при вершине UINT64_MAX - далеко за окном";
}

/**
 * @brief Данные без открытой сессии не принимаются: сначала keep-alive со свежим временем.
 */
TEST(PeerState, DataNeedsKeepAliveFirst) {
    PeerState p;
    EXPECT_EQ(name(p.check(hdr(NOW, 0), std::nullopt, NOW)), name(Verdict::UNKNOWN_SESSION));
    EXPECT_EQ(name(p.check(hdr(NOW, 1), NOW, NOW)), name(Verdict::NEW_SESSION));
    EXPECT_EQ(name(p.check(hdr(NOW, 2), std::nullopt, NOW)), name(Verdict::ACCEPT));
    EXPECT_EQ(name(p.check(hdr(NOW, 2), std::nullopt, NOW)), name(Verdict::REPLAY)) << "повтор пакета данных";
    EXPECT_EQ(name(p.check(hdr(NOW, 1), NOW, NOW)), name(Verdict::REPLAY)) << "повтор keep-alive, открывшего сессию";
}

/**
 * @brief Keep-alive с временем дальше MAX_CLOCK_SKEW в любую сторону не открывает сессию;
 * так отбрасывается старый перехваченный keep-alive после перезапуска получателя.
 */
TEST(PeerState, ClockSkew) {
    const std::int64_t skew = MAX_CLOCK_SKEW.count() * SEC;
    for (std::int64_t t : {NOW - skew - 1, NOW + skew + 1, NOW - 3600 * SEC, std::int64_t{INT64_MIN}, std::int64_t{INT64_MAX}}) {
        PeerState p;
        EXPECT_EQ(name(p.check(hdr(NOW, 0), t, NOW)), name(Verdict::CLOCK_SKEW)) << "время keep-alive " << t << ", часы получателя " << NOW;
        EXPECT_FALSE(p.has_session());
    }
    for (std::int64_t t : {NOW - skew, NOW + skew}) {
        PeerState p;
        EXPECT_EQ(name(p.check(hdr(NOW, 0), t, NOW)), name(Verdict::NEW_SESSION)) << "расхождение ровно " << MAX_CLOCK_SKEW.count() << " с";
    }
}

/**
 * @brief Перезапуск отправителя: сессия, начатая позже, заменяет текущую, данные старой больше
 * не принимаются; keep-alive более ранней сессии (повтор после перезапуска) отбрасывается.
 */
TEST(PeerState, SessionChange) {
    PeerState p;
    const std::int64_t old_start = NOW - 600 * SEC;
    ASSERT_EQ(name(p.check(hdr(old_start, 0), NOW, NOW)), name(Verdict::NEW_SESSION));
    ASSERT_EQ(name(p.check(hdr(old_start, 500), std::nullopt, NOW)), name(Verdict::ACCEPT)) << "долгая сессия: начата 10 минут назад";

    EXPECT_EQ(name(p.check(hdr(NOW, 0), NOW, NOW)), name(Verdict::NEW_SESSION)) << "отправитель перезапущен";
    EXPECT_EQ(name(p.check(hdr(NOW, 1), std::nullopt, NOW)), name(Verdict::ACCEPT)) << "номера новой сессии с начала";
    EXPECT_EQ(name(p.check(hdr(old_start, 501), std::nullopt, NOW)), name(Verdict::UNKNOWN_SESSION)) << "данные прежней сессии";
    EXPECT_EQ(name(p.check(hdr(old_start, 502), NOW, NOW)), name(Verdict::STALE_SESSION)) << "свежий по времени keep-alive прежней сессии";
    EXPECT_EQ(name(p.check(hdr(NOW, 3, 8), NOW, NOW)), name(Verdict::STALE_SESSION)) << "та же наносекунда начала, другая случайная часть";
    EXPECT_EQ(name(p.check(hdr(NOW, 2), std::nullopt, NOW)), name(Verdict::ACCEPT)) << "после отказов текущая сессия работает";
}
