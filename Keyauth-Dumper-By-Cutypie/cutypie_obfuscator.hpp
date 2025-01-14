#pragma once
#include <cstddef>
#include <iostream>
#include <utility>
#include <array>
#include <ctime>
#include <cstdint>

// define your secret key here (must be 16 bit = 15 characters only):
constexpr char Secret_Key[] = "XGDD6DFN97DN7SNF";

#define COMPLEX_FLOW() do \
{ \
    volatile int state = 100; \
    for (volatile int i = 0; i < 10; i++) \
    { \
        state = state ^ (i * 0x1234); \
        if (state & 0x1) \
        { \
            volatile int x = state * 0xDEAD; \
            if (x & 0x2) \
            { \
                state ^= 0xBEEF; \
            } \
            else \
            { \
                state += 0xFACE; \
            } \
        } \
        else if (state & 0x2) \
        { \
            volatile int y = state + 0xABCD; \
            switch (y & 0x3) \
            { \
                case 0: \
                    state *= 0x1111; \
                    break; \
                case 1: \
                    state ^= 0x2222; \
                    break; \
                case 2: \
                    state += 0x3333; \
                    break; \
                default: \
                    state -= 0x4444; \
            } \
        } \
        else \
        { \
            state = ~state; \
        } \
        while (state & 0x4) \
        { \
            state = (state << 1) ^ 0x5555; \
            if (state & 0x8) break; \
        } \
        switch(i % 4) \
        { \
            case 0: \
                state += state * 0x1234; \
                if (state & 0x16) continue; \
                break; \
            case 1: \
                state ^= state + 0x5678; \
                if (state & 0x32) break; \
                continue; \
            case 2: \
                state = state ^ 0x9ABC; \
                if (state & 0x64) break; \
                state *= 2; \
                break; \
            default: \
                state = ~(state * 0xDEF0); \
        } \
    } \
} while(0)

#define Initialize() do \
{ \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
    COMPLEX_FLOW(); \
} while(0)

template<size_t n>
class cutypie_Obfusactor {
public:
    static constexpr size_t k = sizeof(Secret_Key) - 1;
    constexpr cutypie_Obfusactor(const char(&str)[n]) : obfuscated(obfuscate_string(str, std::make_index_sequence<n>{})) {}

    const char* decrypt() const { //decrypt at runtime
        static char decrypted[n];
        for (size_t i = 0; i < n; ++i) {
            decrypted[i] = static_cast<char>(obfuscated[i] ^ (Secret_Key[i % k] ^ (0xC2 + 0xAB)));
        }
        decrypted[n - 1] = '\0';
        return decrypted;
    }

private:
    const std::array<char, n> obfuscated; //store the encrypted string

    template<size_t... indexes>
    static constexpr std::array<char, n> obfuscate_string(const char(&str)[n], std::index_sequence<indexes...>) {
        return { (static_cast<char>((str[indexes] ^ (Secret_Key[indexes % k] ^ (0xC2 + 0xAB)))))... };
    }
};

template<size_t N>
constexpr cutypie_Obfusactor<N> make_obfuscated(const char(&input)[N]) {
    return cutypie_Obfusactor<N>(input);
}

#define C_OBF(str) make_obfuscated(str)