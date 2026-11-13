#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "crypto.hpp"

/**
 * @brief Окно принятых номеров пакетов (RFC 6479): повтор и слишком старые номера отбрасываются.
 *
 * Хранит наибольший принятый номер и битовую карту последних SIZE номеров. Пакеты, пришедшие
 * не по порядку в пределах окна, принимаются по одному разу.
 */
class ReplayWindow {
   public:
    /** @brief Сколько последних номеров помнит окно. */
    static constexpr std::uint64_t SIZE = 2048;

    /**
     * @brief Принимает номер, если его ещё не было и он не старше окна; принятый запоминается.
     * @return true - номер новый
     */
    bool accept(std::uint64_t seq);

    /** @brief Забывает все номера: следующий accept() примет любой. */
    void reset();

   private:
    static constexpr std::size_t WORD_BITS = 64;

    std::array<std::uint64_t, SIZE / WORD_BITS> m_bits{};
    std::uint64_t m_top = 0;
    bool m_empty = true;
};

/** @brief Допустимое расхождение часов собеседников при начале сессии. */
inline constexpr std::chrono::seconds MAX_CLOCK_SKEW{60};

/** @brief Текущее время CLOCK_REALTIME в наносекундах от эпохи Unix. */
std::int64_t wall_clock_ns();

/**
 * @brief Сессия собеседника и окно её номеров: решает, принять ли расшифрованный пакет.
 *
 * Пакеты текущей сессии проходят через ReplayWindow. Новую сессию открывает только keep-alive,
 * время в котором отличается от своих часов не больше MAX_CLOCK_SKEW, и только если она начата
 * позже текущей. Так старый перехваченный трафик не принимается даже после перезапуска получателя,
 * хотя окна на диске не хранятся.
 */
class PeerState {
   public:
    /** @brief Решение по пакету. */
    enum class Verdict {
        ACCEPT,          ///< пакет текущей сессии, номер новый
        NEW_SESSION,     ///< keep-alive открыл новую сессию
        REPLAY,          ///< номер уже был или старше окна
        UNKNOWN_SESSION, ///< данные чужой сессии: ждём её keep-alive
        STALE_SESSION,   ///< keep-alive сессии, начатой не позже текущей
        CLOCK_SKEW,      ///< keep-alive с временем дальше MAX_CLOCK_SKEW от своих часов
    };

    /**
     * @brief Проверяет пакет и при принятии запоминает его номер.
     * @param header заголовок расшифрованного пакета
     * @param keep_alive_time_ns время из keep-alive; nullopt для пакетов данных
     * @param now_ns свои часы, wall_clock_ns()
     */
    Verdict check(const PacketHeader& header, std::optional<std::int64_t> keep_alive_time_ns, std::int64_t now_ns);

    /** @brief Открыта ли сессия. */
    bool has_session() const { return m_has_session; }

    /** @brief Принято ли решение: пакет можно обрабатывать. */
    static bool accepted(Verdict v) { return v == Verdict::ACCEPT || v == Verdict::NEW_SESSION; }

   private:
    ReplayWindow m_window;
    SessionId m_session;
    bool m_has_session = false;
};

/** @brief Название решения для журнала. */
const char* verdict_name(PeerState::Verdict v);
