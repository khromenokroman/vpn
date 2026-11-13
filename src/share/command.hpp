#pragma once

#include <string>
#include <vector>

/**
 * @brief Запускает внешнюю программу без shell и ждёт её завершения.
 *
 * Аргументы передаются в execve как есть, поэтому значения вроде "1.2.3.4; rm -rf /" не интерпретируются.
 * Программа ищется в PATH. В дочернем процессе снимается маска сигналов, заблокированных под signalfd.
 *
 * @param argv программа и аргументы, не пустой
 * @param quiet true - вывод программы подавляется и ненулевой код не пишется в журнал
 * @return код завершения программы; -1, если не удалось запустить или она убита сигналом
 */
int run_command(const std::vector<std::string>& argv, bool quiet = false);

/** @brief Склеивает argv в строку для журнала. */
std::string command_to_string(const std::vector<std::string>& argv);
