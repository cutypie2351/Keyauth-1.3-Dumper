#pragma once
#include <windows.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>


struct result_t
{
public:
	result_t() = default;

	result_t(std::uintptr_t address) : m_address(address)
	{

	}

	std::uintptr_t rva(std::int16_t size) const noexcept { return m_address ? (m_address + size + (uintptr_t) * (int*)(m_address + (size - sizeof(int)))) : 0; }
	std::uintptr_t get() const noexcept { return m_address; }

private:
	std::uintptr_t m_address;
};

class c_scanner
{
public:
	explicit c_scanner() noexcept;

	[[nodiscard]] result_t find_pattern(const std::string& pattern) noexcept;

private:
	std::uintptr_t main_module = { };
private:
	std::vector<std::int16_t> pattern_to_byte(const std::string& pattern);
};

std::shared_ptr<c_scanner> scanner();