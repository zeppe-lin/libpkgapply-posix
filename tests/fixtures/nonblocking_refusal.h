// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cerrno>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace pkgapply::test {

inline bool replace_with_fifo(const std::string& path)
{
  if (::unlink(path.c_str()) != 0)
    return false;
  return ::mkfifo(path.c_str(), 0600) == 0;
}

template<class Probe>
bool refuses_without_blocking(Probe&& probe)
{
  const pid_t child = ::fork();
  if (child < 0)
    return false;
  if (child == 0) {
    ::alarm(2);
    bool refused = false;
    try {
      refused = probe();
    } catch (...) {
      refused = false;
    }
    ::_exit(refused ? 0 : 1);
  }

  int status = 0;
  for (;;) {
    const pid_t result = ::waitpid(child, &status, 0);
    if (result == child)
      break;
    if (result < 0 && errno == EINTR)
      continue;
    return false;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace pkgapply::test
