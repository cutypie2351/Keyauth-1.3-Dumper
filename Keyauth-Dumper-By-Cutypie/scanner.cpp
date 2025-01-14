#include "scanner.h"


c_scanner::c_scanner() noexcept
{
	this->main_module = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

result_t c_scanner::find_pattern(const std::string& pattern) noexcept
{
	const auto pattern_bytes = pattern_to_byte(pattern);

	const auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(this->main_module);
	const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::uint8_t*>(this->main_module) + dos_headers->e_lfanew);

	const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;

	auto scan_bytes = reinterpret_cast<std::uint8_t*>(this->main_module);

	for (auto i = 0ul; i < size_of_image - pattern_bytes.size(); ++i) {
		bool found = true;
		for (auto j = 0ul; j < pattern_bytes.size(); ++j) {
			if (scan_bytes[i + j] != pattern_bytes.data()[j] && pattern_bytes.data()[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return result_t(reinterpret_cast<std::uintptr_t>(&scan_bytes[i]));
		}
	}

	return { };
}

std::vector<std::int16_t> c_scanner::pattern_to_byte(const std::string& pattern)
{
	std::vector<std::int16_t> bytes = { };

	const auto start = const_cast<char*>(&pattern[0]);
	const auto end = const_cast<char*>(&pattern[0]) + pattern.size();

	for (auto current = start; current < end; ++current) {
		if (*current == '?') {
			++current;
			if (*current == '?')
				++current;
			bytes.push_back(-1);
		}
		else {
			bytes.push_back(strtoul(current, &current, 16));
		}
	}

	return bytes;
}

std::shared_ptr<c_scanner> scanner()
{
	static auto instance = std::make_shared<c_scanner>();
	return instance;
}
