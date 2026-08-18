// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/libpkgapply-posix.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <type_traits>
#include <unistd.h>

static_assert(std::is_base_of_v<
    pkgapply::application_backend,
    pkgapply::posix::application_posix_backend>);
static_assert(std::is_base_of_v<
    pkgapply::target_mutation_lease,
    pkgapply::posix::target_mutation_lease>);

namespace {

class temporary_directory final {
public:
  temporary_directory()
  {
    constexpr std::string_view seed =
        "/tmp/libpkgapply-posix-installed-XXXXXX";
    static_assert(seed.size() + 1U <= 64U);
    std::memcpy(pattern_.data(), seed.data(), seed.size());
    pattern_[seed.size()] = '\0';
    char* value = ::mkdtemp(pattern_.data());
    if (value != nullptr)
      path_ = value;
  }

  ~temporary_directory()
  {
    if (!path_.empty())
      static_cast<void>(::rmdir(path_.c_str()));
  }

  [[nodiscard]] bool valid() const noexcept { return !path_.empty(); }
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
  std::array<char, 64> pattern_{};
  std::string path_;
};

} // namespace

int main()
{
  if (pkgapply::posix::version() != "3.2.2" ||
      pkgapply::posix::api_version != 2)
  {
    return 1;
  }

  temporary_directory directory;
  if (!directory.valid())
    return 2;

  auto observer =
      pkgapply::posix::application_target_observer::open(directory.path());
  const auto path = pkgplan::package_path::parse("missing");
  const auto observations = observer.observe({path});
  const auto* observed = observations.find(path);
  if (observed == nullptr || observed->state() != pkgapply::fact_state::not_applicable)
    return 3;

  auto rejected =
      pkgapply::posix::application_rejected_object_store::open(directory.path());
  static_cast<void>(rejected);
  return 0;
}
