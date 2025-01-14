#define _CRT_SECURE_NO_WARNINGS
#include "minhook/MinHook.h"
#include "xorstr.hpp"
#include "scanner.h"
#include <windows.h>
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <fstream>
#include <polyhook2/Detour/x64Detour.hpp>
#include <polyhook2/ZydisDisassembler.hpp>
#include <Windows.h>
#include <polyhook2/IHook.hpp>
#include "json.hpp"
#include <regex>
#include <chrono>
#include <sstream>
#include <filesystem>
#include <polyhook2/Detour/NatDetour.hpp>


class fn_ptr {
public:
	using request_function = std::string(*)(std::string, std::string);
	using error_function = void(*)(std::string);
	using integrity_check_function = auto(*)(const char*, bool) -> bool;

	request_function keyauth_request_address_original = nullptr;
	error_function keyauth_error_address_original = nullptr;
	integrity_check_function keyauth_integrity_check_original = nullptr;
	PLH::NatDetour* keyauthDetour = nullptr;
	PLH::NatDetour* keyauthDetour2 = nullptr;

	PLH::x64Detour* detourx64 = nullptr;
	PLH::x64Detour* detourx64_2 = nullptr;
	static std::string hexDecode(const std::string& hex)
	{
		int len = hex.length();
		std::string newString;
		for (int i = 0; i < len; i += 2)
		{
			std::string byte = hex.substr(i, 2);
			char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
			newString.push_back(chr);
		}
		return newString;
	}
	int GetInstructionLength(DWORD_PTR address) {

		const int bufferSize = 15;
		unsigned char buffer[bufferSize];

		if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), buffer, bufferSize, nullptr)) {
			return -1;
		}

		int length = 0;
		while (length < bufferSize && buffer[length] != 0xC3) {
			length++;
		}

		return length;
	}
	bool nop_memory(DWORD_PTR address)
	{
		DWORD oldProtect;

		size_t size = GetInstructionLength(address);

		if (size <= 0) {
			MessageBoxA(NULL, xorstr_("Invalid instruction length"), xorstr_("cracked"), MB_ICONERROR | MB_OK);
			return false;
		}

		if (VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			memset(reinterpret_cast<void*>(address), 0x90, size);
			VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &oldProtect);
			return true;
		}
		else {
			int error = GetLastError();
			printf(xorstr_("Failed to NOP memory at 0x%lX. Error code: %i"), address, error);
			return false;
		}
	}

	void remove_global_check(uintptr_t start_address) {
		size_t size = GetInstructionLength(start_address);
		DWORD oldProtect;
		VirtualProtect(reinterpret_cast<LPVOID>(start_address), size, PAGE_EXECUTE_READWRITE, &oldProtect);

		memset(reinterpret_cast<LPVOID>(start_address), 0x90, size);

		VirtualProtect(reinterpret_cast<LPVOID>(start_address), size, oldProtect, &oldProtect);
	}

	void patch_siganture(uintptr_t address) {
		DWORD oldProtect;
		VirtualProtect(reinterpret_cast<LPVOID>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect);

		*reinterpret_cast<BYTE*>(address) = 0x75;

		VirtualProtect(reinterpret_cast<LPVOID>(address), 1, oldProtect, &oldProtect);
	}

}; static fn_ptr* functions = new fn_ptr();

class keyauth_dumper {
public:
	//std::string successJson = xorstr_(R"({"success":true,"message":"Logged into cracked","info":{"username":"cracked","subscriptions":[{"subscription":"default","key":"cracked","expiry":"132353782990","timeleft":130645673640}],"ip":"191.129.123.134","hwid":"S-5-5-25-9-9-9-6969","createdate":"1708109350","lastlogin":"1708109350"},"nonce":"5a37ff61-1777-409d-98c6-17a51cdceaef"})");
	
	std::string current_time_as_string() {
		auto now = std::chrono::system_clock::now();
		auto time = std::chrono::system_clock::to_time_t(now);
		std::tm* tmPtr = std::localtime(&time);
		int year = tmPtr->tm_year + 1900;
		int month = tmPtr->tm_mon + 1;
		int day = tmPtr->tm_mday;
		int hour = tmPtr->tm_hour;
		int minute = tmPtr->tm_min;
		std::ostringstream oss;
		oss << std::setw(4) << std::setfill('0') << year << "-"
			<< std::setw(2) << std::setfill('0') << month << "-"
			<< std::setw(2) << std::setfill('0') << day << "-"
			<< std::setw(2) << std::setfill('0') << hour << "-"
			<< std::setw(2) << std::setfill('0') << minute;
		return oss.str();
	}


}; static keyauth_dumper* keyauth_main = new keyauth_dumper();

class func_hooks {
public:


	std::string download_dumper(std::string data, std::string url) {

		MessageBoxA(NULL, xorstr_("Dumper Hooked Successfully"), xorstr_("Keyauth Dumper By Cutypie"), MB_OK);
		std::string result = functions->keyauth_request_address_original(data, url);

		/*if (keyauth_main->log_requests) {
			std::ofstream logging("Logs.txt", std::ios::app);
			while (logging.is_open()) {
				logging << data << url;
				logging.close();
			}
		}*/
		nlohmann::json intercepter;
		try {
			intercepter = nlohmann::json::parse(result);
		}
		catch (const std::exception& exception) {
			MessageBoxA(NULL, exception.what(), "json parse failure.", MB_OK | MB_ICONERROR);
			return result;
		}

		if (data.find("type=file&fileid=") != std::string::npos) {

			std::regex regex_scanning("\\b\\d{6}\\b");
			std::sregex_iterator iteration(data.begin(), data.end(), regex_scanning);
			std::sregex_iterator end_iteration;
			std::string searchable_fileid;
			static int count = 1;

			if (iteration != end_iteration) {
				std::smatch match = *iteration;

				searchable_fileid = match.str();

				nlohmann::json intercepter;
				auto json = intercepter.parse(result);
				if (json.contains("contents")) {
					std::string file_contents_decoded = functions->hexDecode(json[("contents")]);
					std::vector<unsigned char> file_data(file_contents_decoded.begin(), file_contents_decoded.end());
					if (!file_data.empty()) {
						std::string current_time = keyauth_main->current_time_as_string();
						std::string folder_name = "dump files";
						std::string file_path = folder_name + "\\" + "file_dump_" + std::to_string(count) + ".bin";
						count++;
						if (!std::filesystem::exists("dump files"))
						{
							CreateDirectoryA(folder_name.c_str(), nullptr);

						}
						std::ofstream dumped_file(file_path, std::ios::out | std::ios::binary);
						while (dumped_file.is_open()) {
							dumped_file.write(reinterpret_cast<char*>(file_data.data()), file_data.size());
							dumped_file.close();
							std::string success = "file dumped successfully into: " + file_path;
							MessageBoxA(NULL, success.c_str(), "Keyauth Dumper by Cutypie", MB_OK | MB_ICONINFORMATION);
						}
					}
				}
			}
		}
	}

	std::string error_bypass(std::string message) {
		return "";
	}
	auto integrity_check_bypass(const char* section, bool fix) -> bool {
		return false;
	}

}; static func_hooks* hooks = new func_hooks();

class signatures {
private:
	bool isImGui = false;
public:
	std::uintptr_t keyauth_request_sig;
	std::uintptr_t keyauth_request_imgui_sig;
	std::uintptr_t keyauth_error_sig;
	std::uintptr_t keyauth_integrity_check_sig;
	std::uintptr_t keyauth_command_error_sig;
	std::uintptr_t keyauth_sig_check_bypass_sig;
	std::uintptr_t keyauth_sig_check_bypass_sig2;
	std::uintptr_t keyauth_modify_sig;

	void hook_sigs() {
		keyauth_request_sig = scanner()->find_pattern(xorstr_("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC 90 01 00 00")).get();
		keyauth_request_imgui_sig = scanner()->find_pattern(xorstr_("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC A0 01 00 00")).get();
		keyauth_error_sig = scanner()->find_pattern(xorstr_("48 89 5C 24 10 48 89 74 24 18 57 48 81 EC")).get();
		keyauth_integrity_check_sig = scanner()->find_pattern(xorstr_("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 81 EC 80 02 00 00")).get();
		keyauth_command_error_sig = scanner()->find_pattern(xorstr_("48 89 5C 24 10 57 48 81 EC A0")).get();
		keyauth_sig_check_bypass_sig = scanner()->find_pattern(xorstr_("0F 84 ? ? ? ? 4C 8D 3D ? ? ? ? 49 8B F7 48 83 3D")).get();
		keyauth_sig_check_bypass_sig2 = scanner()->find_pattern(xorstr_("0F 84 ? ? ? ? 4C 8D 25 ? ? ? ? 49 8B F4")).get();
		keyauth_modify_sig = scanner()->find_pattern(xorstr_("48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 41 56")).get();

		void* keyauth_request_sig_ptr = reinterpret_cast<void*>(keyauth_request_sig);
		void* keyauth_request_imgui_sig_ptr = reinterpret_cast<void*>(keyauth_request_imgui_sig);
		void* keyauth_error_sig_ptr = reinterpret_cast<void*>(keyauth_error_sig);
		void* keyauth_integrity_check_sig_ptr = reinterpret_cast<void*>(keyauth_integrity_check_sig);
		void* keyauth_sig_check_bypass_sig2_ptr = reinterpret_cast<void*>(keyauth_sig_check_bypass_sig2);

		if (keyauth_request_sig_ptr == nullptr || keyauth_error_sig_ptr == nullptr || keyauth_integrity_check_sig_ptr == nullptr)
		{
			MessageBoxA(NULL, xorstr_("Hooks Failed :("), xorstr_("Keyauth Dumper By Cutypie"), MB_OK | MB_ICONINFORMATION);
		}
		else
		{
			MessageBoxA(NULL, xorstr_("Hooked All Succesfully!"), xorstr_("Keyauth Dumper By Cutypie"), MB_OK | MB_ICONINFORMATION);
		}

		if (keyauth_sig_check_bypass_sig2_ptr != nullptr)
		{
			isImGui = true;
		}

	}

	static std::string dumper_hook(std::string data, std::string url) {
		return hooks->download_dumper(data, url);
	}
	static std::string error_bypass_hook(std::string message) {
		return hooks->error_bypass(message);
	}
	static bool integrity_check_bypass_hook(const char* section, bool fix) {
		return hooks->integrity_check_bypass(section, fix);
	}

	

	void initialize_hooks() {
		MH_Initialize();

		if (MH_CreateHook((void**)keyauth_integrity_check_sig, &integrity_check_bypass_hook, reinterpret_cast<void**>(&functions->keyauth_integrity_check_original)) != MH_OK) {
			MessageBoxW(NULL, xorstr_(L"failed to hook keyauth integrity check"), xorstr_(L"Keyauth Dumper By Cutypie"), MB_OK);
		}
		if (isImGui)
		{
			if (MH_CreateHook((void**)keyauth_request_imgui_sig, &dumper_hook, reinterpret_cast<LPVOID*>(&functions->keyauth_request_address_original)) != MH_OK) {
				MessageBoxW(NULL, xorstr_(L"failed to hook keyauth requests"), xorstr_(L"Keyauth Dumper By Cutypie"), MB_OK);
			}
		}
		else
		{
			if (MH_CreateHook((void**)keyauth_request_sig, &dumper_hook, reinterpret_cast<LPVOID*>(&functions->keyauth_request_address_original)) != MH_OK) {
				MessageBoxW(NULL, xorstr_(L"failed to hook keyauth imgui requests"), xorstr_(L"Keyauth Dumper By Cutypie"), MB_OK);
			}
		}

		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
			MessageBoxW(NULL, xorstr_(L"failed to enable all hooks."), xorstr_(L"Keyauth Dumper By Cutypie"), MB_OK);
		}

		functions->patch_siganture(keyauth_sig_check_bypass_sig);
		if (isImGui)
		{
			functions->patch_siganture(keyauth_sig_check_bypass_sig2);
		}
		


	}

	void* allocate_executable_memory(size_t size) {
		void* allocated = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!allocated) {
			MessageBoxA(NULL, "Failed to allocate executable memory!", "Error", MB_OK);
		}
		return allocated;
	}


	bool WaitForUnpack(PVOID address) {
		MEMORY_BASIC_INFORMATION mbi;
		for (int i = 0; i < 10; i++) {
			if (VirtualQuery(address, &mbi, sizeof(mbi))) {
				if (mbi.Protect & PAGE_EXECUTE_READ ||
					mbi.Protect & PAGE_EXECUTE_READWRITE) {
					return true;
				}
			}
			Sleep(100);
		}
		return false;
	}

	void initialize_polyhook()
	{
		

		PLH::ZydisDisassembler dis(PLH::Mode::x64);

		if (!WaitForUnpack((PVOID)keyauth_integrity_check_sig)) {
			MessageBoxA(NULL, "Failed to wait for keyauth_integrity_check_sig to unpack!", "Error", MB_OK);
			return;
		}


		functions->detourx64 = new PLH::x64Detour(
			keyauth_integrity_check_sig,
			(uint64_t)&integrity_check_bypass_hook,
			(uint64_t*)&functions->keyauth_integrity_check_original
		);



		if (!functions->detourx64->hook()) {
			MessageBoxA(NULL, "Failed to hook keyauth_integrity_check", "Error", MB_OK);
			return;
		}

		if (!WaitForUnpack((PVOID)keyauth_request_sig)) {
			MessageBoxA(NULL, "Failed to wait for keyauth_request_sig func to unpack!", "Keyauth Dumper By Cutypie", MB_OK);
			return;
		}

		functions->detourx64_2 = new PLH::x64Detour(
			keyauth_request_sig,
			(uint64_t)&dumper_hook,
			(uint64_t*)&functions->keyauth_request_address_original
		);
		if (!functions->detourx64_2->hook()) {
			MessageBoxA(NULL, "Failed to hook keyauth_request", "Keyauth Dumper By Cutypie", MB_OK);
			return;
		}



		MessageBoxW(NULL, xorstr_(L"Hooked successfully!"), xorstr_(L"Keyauth Dumper By Cutypie"), MB_OK);

		functions->patch_siganture(keyauth_sig_check_bypass_sig);
		if (isImGui)
		{
			functions->patch_siganture(keyauth_sig_check_bypass_sig2);
		}
		//OutputDebugStringA("[+] Hooked successfully!\n");

		

	}
}; static signatures* keyauth_sigs = new signatures();