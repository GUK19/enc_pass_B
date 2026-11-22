// PasswordManager.cpp : 애플리케이션에 대한 진입점을 정의합니다.
//

#include "framework.h"
#include "PasswordManager.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <algorithm>
#include <limits>
///////////////////////////////////////////////////
#include <array>
#include <cstring>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
///////////////////////////////////////////////////
#define MAX_LOADSTRING 100


// 전역 변수:
HINSTANCE hInst;                                // 현재 인스턴스입니다.
WCHAR szTitle[MAX_LOADSTRING];                  // 제목 표시줄 텍스트입니다.
WCHAR szWindowClass[MAX_LOADSTRING];            // 기본 창 클래스 이름입니다.


struct PasswordEntry
{
    unsigned int id;
    std::wstring name;
    std::wstring password;
};

std::vector<PasswordEntry> g_entries;
unsigned int g_nextId = 1;

// Registry storage location
constexpr wchar_t REGISTRY_PATH[] =
L"Software\\enc_pass_B\\PasswordManager";
///////////////////////////////////////////////////////////////////////////////////
constexpr wchar_t ENCRYPTED_PATH[] =
L"Software\\enc_pass_B\\PasswordManager\\EncryptedEntries";

constexpr ULONG KEY_BYTES = 32;
constexpr ULONG SALT_BYTES = 16;
constexpr ULONG NONCE_BYTES = 12;
constexpr ULONG TAG_BYTES = 16;

constexpr DWORD KDF_ITERATIONS = 600000;
constexpr UINT WM_PM_UNLOCK = WM_APP + 1;

enum class MasterMode {
    Setup,
    Unlock,
    EncryptAdd
};

MasterMode g_masterMode = MasterMode::Setup;
bool g_masterEnabled = false;
bool g_storageReady = false;


///////////////////////////////////////////////////////////////////////

HWND g_nameEdit = nullptr;

HWND g_passwordEdit = nullptr;
HWND g_listBox = nullptr;
HWND g_statusLabel = nullptr; // 추가


// 마스터 암호용 추가 시작
HWND g_masterWindow = nullptr;
HWND g_masterInput = nullptr;
HWND g_masterConfirm = nullptr;
HWND g_masterOk = nullptr;
// 마스터 암호용 추가 끝
bool g_showPassword = false;

// Control IDs
constexpr int ID_PM_NAME = 2001;
constexpr int ID_PM_PASSWORD = 2002;
constexpr int ID_PM_LIST = 2003;
constexpr int ID_PM_ADD = 2004;
constexpr int ID_PM_LOAD = 2005;
constexpr int ID_PM_DELETE = 2006;
constexpr int ID_PM_SHOW = 2007;
//마스터 암호용 추가 시작
constexpr int ID_PM_MASTER = 2008;

constexpr int ID_MASTER_INPUT = 2101;
constexpr int ID_MASTER_CONFIRM = 2102;
constexpr int ID_MASTER_SHOW = 2103;
constexpr int ID_MASTER_OK = 2104;
constexpr int ID_MASTER_CANCEL = 2105;
//마스터 암호용 추가 끝

// Create a GUI control
HWND CreateControl(
    HWND parent,
    LPCWSTR className,
    LPCWSTR text,
    DWORD style,
    DWORD exStyle,
    int x, int y,
    int width, int height,
    int id)
{
    HWND control = CreateWindowExW(
        exStyle,
        className,
        text,
        WS_CHILD | WS_VISIBLE | style,
        x, y, width, height,
        parent,
        reinterpret_cast<HMENU>(
            static_cast<INT_PTR>(id)),
        hInst,
        nullptr
    );

    if (control)
    {
        SendMessageW(
            control,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(
                GetStockObject(DEFAULT_GUI_FONT)),
            TRUE
        );
    }

    return control;
}

// Read the contents of a text input
std::wstring ReadControlText(HWND control)
{
    int length = GetWindowTextLengthW(control);

    std::wstring text(length + 1, L'\0');

    int copied = GetWindowTextW(
        control, &text[0], length + 1
    );

    text.resize(copied);

    return text;
}
// Convert UTF-16 code units to hexadecimal text.
std::wstring EncodeHex(const std::wstring& source)
{
    const wchar_t* digits = L"0123456789ABCDEF";

    std::wstring result;
    result.reserve(source.size() * 4);

    for (wchar_t ch : source)
    {
        unsigned int value =
            static_cast<unsigned int>(
                static_cast<uint16_t>(ch));

        result.push_back(digits[(value >> 12) & 0xF]);
        result.push_back(digits[(value >> 8) & 0xF]);
        result.push_back(digits[(value >> 4) & 0xF]);
        result.push_back(digits[value & 0xF]);
    }

    return result;
}

// Convert one hexadecimal character to a number.
int HexDigit(wchar_t c)
{
    if (c >= L'0' && c <= L'9')
        return c - L'0';

    if (c >= L'A' && c <= L'F')
        return c - L'A' + 10;

    if (c >= L'a' && c <= L'f')
        return c - L'a' + 10;

    return -1;
}

// Convert hexadecimal text back to UTF-16 text.
bool DecodeHex(
    const std::wstring& source,
    std::wstring& result)
{
    if (source.size() % 4 != 0)
        return false;

    std::wstring decoded;
    decoded.reserve(source.size() / 4);

    for (size_t i = 0; i < source.size(); i += 4)
    {
        unsigned int value = 0;

        for (size_t j = 0; j < 4; ++j)
        {
            int digit = HexDigit(source[i + j]);

            if (digit < 0)
                return false;

            value = (value << 4) | digit;
        }

        if (value == 0)
            return false;

        decoded.push_back(
            static_cast<wchar_t>(value));
    }

    result = std::move(decoded);
    return true;
}

// Standard CRC-32 over ASCII-format registry text.
uint32_t CalculateCrc32(const std::wstring& ascii)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (wchar_t c : ascii)
    {
        crc ^= static_cast<uint8_t>(c);

        for (int i = 0; i < 8; ++i)
        {
            crc = (crc >> 1) ^
                ((crc & 1u) ? 0xEDB88320u : 0u);
        }
    }

    return ~crc;
}

// Format a 32-bit number as eight hex characters.
std::wstring Hex8(uint32_t value)
{
    const wchar_t* digits = L"0123456789ABCDEF";
    std::wstring result(8, L'0');

    for (int i = 7; i >= 0; --i)
    {
        result[i] = digits[value & 0xF];
        value >>= 4;
    }

    return result;
}


// Save one password entry as a separate REG_SZ value.
// Save one password entry as a separate REG_SZ value.
bool SaveEntryToRegistry(
    unsigned int number,
    const std::wstring& name,
    const std::wstring& password)
{
    // Registry value name: number_name
    std::wstring valueName =
        std::to_wstring(number) + L"_" + name;

    // Registry data: number + name HEX + password HEX
    std::wstring data =
        std::to_wstring(number) +
        EncodeHex(name) +
        EncodeHex(password);

    // Append CRC-32.
    data += L"#" + Hex8(CalculateCrc32(data));

    HKEY key = nullptr;

    LONG status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        nullptr
    );

    if (status != ERROR_SUCCESS)
        return false;

    DWORD byteCount = static_cast<DWORD>(
        (data.size() + 1) * sizeof(wchar_t)
        );

    status = RegSetValueExW(
        key,
        valueName.c_str(),
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(data.c_str()),
        byteCount
    );

    RegCloseKey(key);

    return status == ERROR_SUCCESS;
}


bool ParseEntryNumber(
    const std::wstring& text,
    unsigned int& number)
{
    if (text.empty())
        return false;

    unsigned int result = 0;
    const unsigned int maximum =
        (std::numeric_limits<unsigned int>::max)();

    for (wchar_t c : text)
    {
        if (c < L'0' || c > L'9')
            return false;

        unsigned int digit = c - L'0';

        if (result > (maximum - digit) / 10)
            return false;

        result = result * 10 + digit;
    }

    if (result == 0 ||
        std::to_wstring(result) != text)
        return false;

    number = result;
    return true;
}

// Load all password entries from the registry.
bool LoadEntriesFromRegistry()
{
    HKEY key = nullptr;

    LONG status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        0,
        KEY_READ,
        &key
    );

    // The registry key may not exist on first launch.
    if (status == ERROR_FILE_NOT_FOUND)
    {
        g_entries.clear();
        g_nextId = 1;
        return true;
    }

    if (status != ERROR_SUCCESS)
        return false;

    DWORD maxNameLength = 0;

    status = RegQueryInfoKeyW(
        key,
        nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr,
        nullptr,
        &maxNameLength,
        nullptr, nullptr, nullptr
    );

    if (status != ERROR_SUCCESS)
    {
        RegCloseKey(key);
        return false;
    }

    std::vector<wchar_t> nameBuffer(
        static_cast<size_t>(maxNameLength) + 2
    );

    std::vector<PasswordEntry> loaded;
    unsigned int largestId = 0;
    bool success = true;

    for (DWORD i = 0; ; ++i)
    {
        DWORD nameLength =
            static_cast<DWORD>(nameBuffer.size());

        status = RegEnumValueW(
            key,
            i,
            nameBuffer.data(),
            &nameLength,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );

        if (status == ERROR_NO_MORE_ITEMS)
            break;

        if (status != ERROR_SUCCESS)
        {
            success = false;
            break;
        }

        std::wstring valueName(
            nameBuffer.data(), nameLength
        );

        // New entry names follow number_name.
        // Ignore the earlier test value named "1".
        size_t separator = valueName.find(L'_');

        if (separator == std::wstring::npos)
            continue;

        unsigned int id = 0;

        if (!ParseEntryNumber(
            valueName.substr(0, separator), id) ||
            separator + 1 >= valueName.size())
        {
            success = false;
            break;
        }

        std::wstring name =
            valueName.substr(separator + 1);

        // Find the required data buffer size.
        // Find the required data buffer size.
        DWORD bytes = 0;

        status = RegGetValueW(
            key,
            nullptr,              // Subkey: 현재 열려 있는 키 사용
            valueName.c_str(),    // 읽을 레지스트리 값 이름
            RRF_RT_REG_SZ,
            nullptr,
            nullptr,
            &bytes
        );

        if (status != ERROR_SUCCESS ||
            bytes < sizeof(wchar_t) ||
            bytes % sizeof(wchar_t) != 0)
        {
            success = false;
            break;
        }

        std::vector<wchar_t> buffer(
            bytes / sizeof(wchar_t) + 1, L'\0'
        );

        DWORD readBytes = static_cast<DWORD>(
            buffer.size() * sizeof(wchar_t)
            );

        status = RegGetValueW(
            key,
            nullptr,              // Subkey: 현재 열려 있는 키 사용
            valueName.c_str(),    // 읽을 레지스트리 값 이름
            RRF_RT_REG_SZ,
            nullptr,
            buffer.data(),
            &readBytes
        );

        if (status != ERROR_SUCCESS ||
            readBytes < sizeof(wchar_t) ||
            readBytes % sizeof(wchar_t) != 0 ||
            buffer[readBytes / sizeof(wchar_t) - 1] != L'\0')
        {
            success = false;
            break;
        }

        std::wstring stored(
            buffer.data(),
            readBytes / sizeof(wchar_t) - 1
        );

        if (stored.find(L'\0') != std::wstring::npos)
        {
            success = false;
            break;
        }

        // Verify CRC-32.
        size_t hashPos = stored.rfind(L'#');

        if (hashPos == std::wstring::npos ||
            stored.size() != hashPos + 9)
        {
            success = false;
            break;
        }

        std::wstring payload = stored.substr(0, hashPos);

        if (stored.substr(hashPos + 1) !=
            Hex8(CalculateCrc32(payload)))
        {
            success = false;
            break;
        }

        // Expected prefix: number + name HEX.
        std::wstring prefix =
            std::to_wstring(id) + EncodeHex(name);

        if (payload.size() <= prefix.size() ||
            payload.compare(0, prefix.size(), prefix) != 0)
        {
            success = false;
            break;
        }

        // The remaining HEX represents the password.
        std::wstring password;

        if (!DecodeHex(
            payload.substr(prefix.size()),
            password) ||
            password.empty())
        {
            success = false;
            break;
        }

        loaded.push_back({ id, name, password });

        if (id > largestId)
            largestId = id;
    }

    RegCloseKey(key);

    if (!success)
        return false;

    // Display in entry-number order.
    std::sort(
        loaded.begin(),
        loaded.end(),
        [](const PasswordEntry& a,
            const PasswordEntry& b)
        {
            return a.id < b.id;
        }
    );

    // Reject duplicate entry IDs.
    for (size_t i = 1; i < loaded.size(); ++i)
    {
        if (loaded[i - 1].id == loaded[i].id)
            return false;
    }

    g_entries = std::move(loaded);

    // Zero means the unsigned ID range was exhausted.
    g_nextId = largestId + 1;
    return true;
}

// Delete one registry value, not the entire key.
bool DeleteEntryFromRegistry(const PasswordEntry& entry)
{
    std::wstring valueName =
        std::to_wstring(entry.id) + L"_" + entry.name;

    HKEY key = nullptr;

    LONG status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        0,
        KEY_SET_VALUE,
        &key
    );

    if (status != ERROR_SUCCESS)
        return false;

    status = RegDeleteValueW(
        key,
        valueName.c_str()
    );

    RegCloseKey(key);

    return status == ERROR_SUCCESS;
}


// Save master password setup status (0 or 1).
bool SaveMasterPasswordEnabled(bool enabled)
{
    HKEY key = nullptr;

    LONG status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        nullptr
    );

    if (status != ERROR_SUCCESS)
        return false;

    DWORD value = enabled ? 1 : 0;

    status = RegSetValueExW(
        key,
        L"MasterPasswordEnabled",
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&value),
        sizeof(value)
    );

    RegCloseKey(key);

    return status == ERROR_SUCCESS;
}

//// Read master password setup status.
// Missing flag is treated as plaintext mode (not as an error).
bool LoadMasterPasswordEnabled(bool& enabled)
{
    DWORD state = 0;
    DWORD bytes = sizeof(state);

    LONG result = RegGetValueW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        L"MasterPasswordEnabled",
        RRF_RT_REG_DWORD,
        nullptr,
        &state,
        &bytes
    );

    if (result == ERROR_FILE_NOT_FOUND)
    {
        enabled = false;
        return true;
    }

    if (result != ERROR_SUCCESS ||
        bytes != sizeof(state) ||
        state > 1)
    {
        return false;
    }

    enabled = (state == 1);

    return true;
}

// Clear wstring contents while its allocated storage still exists.
void WipeText(std::wstring& text)
{
    if (!text.empty()) SecureZeroMemory(&text[0], text.size() * sizeof(wchar_t));
    text.clear();
}

void WipeKey(std::array<BYTE, KEY_BYTES>& key)
{
    SecureZeroMemory(key.data(), key.size());
}

bool GetRandomBytes(BYTE* output, ULONG size)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, output, size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

bool DeriveAesKey(const std::wstring& password,
    const std::array<BYTE, SALT_BYTES>& salt, DWORD iterations,
    std::array<BYTE, KEY_BYTES>& output)
{
    if (password.empty() || iterations < 100000 || iterations > 10000000 ||
        password.size() > (std::numeric_limits<ULONG>::max)() / sizeof(wchar_t))
        return false;

    BCRYPT_ALG_HANDLE hash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hash, BCRYPT_SHA256_ALGORITHM,
        nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return false;

    st = BCryptDeriveKeyPBKDF2(hash,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(password.data())),
        static_cast<ULONG>(password.size() * sizeof(wchar_t)),
        const_cast<PUCHAR>(salt.data()), SALT_BYTES, iterations,
        output.data(), KEY_BYTES, 0);
    BCryptCloseAlgorithmProvider(hash, 0);
    if (!BCRYPT_SUCCESS(st)) WipeKey(output);
    return BCRYPT_SUCCESS(st);
}

// REG_BINARY, format [ 'P','M','0','1' | nonce(12) | tag(16) | ciphertext ]
// The registry value name is authenticated as AAD (not encrypted).
bool AesGcmTransform(bool encrypt,
    const std::array<BYTE, KEY_BYTES>& rawKey,
    const std::wstring& valueName,
    const std::vector<BYTE>& input,
    const BYTE* nonce, BYTE* tag,
    std::vector<BYTE>& output)
{
    if (input.empty() || input.size() > (std::numeric_limits<ULONG>::max)() ||
        valueName.size() > (std::numeric_limits<ULONG>::max)() / sizeof(wchar_t))
        return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE aesKey = nullptr;
    bool ok = false;

    do
    {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_AES_ALGORITHM, nullptr, 0))) break;
        if (!BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) break;
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            alg, &aesKey, nullptr, 0,
            const_cast<PUCHAR>(rawKey.data()), KEY_BYTES, 0))) break;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = NONCE_BYTES;
        info.pbTag = tag;
        info.cbTag = TAG_BYTES;
        info.pbAuthData = reinterpret_cast<PUCHAR>(
            const_cast<wchar_t*>(valueName.data()));
        info.cbAuthData = static_cast<ULONG>(valueName.size() * sizeof(wchar_t));

        output.resize(input.size());
        ULONG written = 0;
        NTSTATUS status = encrypt
            ? BCryptEncrypt(aesKey, const_cast<PUCHAR>(input.data()),
                static_cast<ULONG>(input.size()), &info,
                nullptr, 0, output.data(), static_cast<ULONG>(output.size()),
                &written, 0)
            : BCryptDecrypt(aesKey, const_cast<PUCHAR>(input.data()),
                static_cast<ULONG>(input.size()), &info,
                nullptr, 0, output.data(), static_cast<ULONG>(output.size()),
                &written, 0);
        ok = BCRYPT_SUCCESS(status) && written == input.size();
    } while (false);

    if (aesKey) BCryptDestroyKey(aesKey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok)
    {
        if (!output.empty()) SecureZeroMemory(output.data(), output.size());
        output.clear();
    }
    return ok;
}

bool EncryptText(const std::array<BYTE, KEY_BYTES>& key,
    const std::wstring& valueName, const std::wstring& plain,
    std::vector<BYTE>& record)
{
    if (plain.empty() ||
        plain.size() > (std::numeric_limits<ULONG>::max)() / sizeof(wchar_t))
        return false;
    std::array<BYTE, NONCE_BYTES> nonce{};
    std::array<BYTE, TAG_BYTES> tag{};
    if (!GetRandomBytes(nonce.data(), NONCE_BYTES)) return false;

    // The string is stored on disk as UTF-16LE bytes, not as hex plaintext.
    const BYTE* bytes = reinterpret_cast<const BYTE*>(plain.data());
    std::vector<BYTE> input(bytes, bytes + plain.size() * sizeof(wchar_t));
    std::vector<BYTE> ciphertext;
    bool ok = AesGcmTransform(true, key, valueName, input,
        nonce.data(), tag.data(), ciphertext);
    if (!input.empty()) SecureZeroMemory(input.data(), input.size());
    if (!ok) return false;

    record = { 'P', 'M', '0', '1' };
    record.insert(record.end(), nonce.begin(), nonce.end());
    record.insert(record.end(), tag.begin(), tag.end());
    record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    return true;
}

bool DecryptText(const std::array<BYTE, KEY_BYTES>& key,
    const std::wstring& valueName, const std::vector<BYTE>& record,
    std::wstring& plain)
{
    constexpr size_t HEADER = 4 + NONCE_BYTES + TAG_BYTES;
    if (record.size() <= HEADER || record[0] != 'P' ||
        record[1] != 'M' || record[2] != '0' || record[3] != '1') return false;

    const BYTE* nonce = record.data() + 4;
    std::array<BYTE, TAG_BYTES> tag{};
    std::copy(record.begin() + 4 + NONCE_BYTES,
        record.begin() + HEADER, tag.begin());
    std::vector<BYTE> ciphertext(record.begin() + HEADER, record.end());
    std::vector<BYTE> decoded;
    bool ok = AesGcmTransform(false, key, valueName, ciphertext,
        nonce, tag.data(), decoded);
    if (!ok || decoded.empty() || decoded.size() % sizeof(wchar_t) != 0)
    {
        if (!decoded.empty()) SecureZeroMemory(decoded.data(), decoded.size());
        return false;
    }
    std::wstring result(decoded.size() / sizeof(wchar_t), L'\0');
    std::memcpy(&result[0], decoded.data(), decoded.size());
    SecureZeroMemory(decoded.data(), decoded.size());
    if (result.find(L'\0') != std::wstring::npos)
    {
        WipeText(result);
        return false;
    }
    plain = std::move(result);
    return true;
}

bool WriteBinaryValue(HKEY key, const wchar_t* name,
    const std::vector<BYTE>& value)
{
    if (value.size() > (std::numeric_limits<DWORD>::max)()) return false;
    return RegSetValueExW(key, name, 0, REG_BINARY, value.data(),
        static_cast<DWORD>(value.size())) == ERROR_SUCCESS;
}

bool ReadBinaryValue(HKEY key, const wchar_t* name,
    std::vector<BYTE>& value)
{
    DWORD bytes = 0;
    LONG rc = RegGetValueW(key, nullptr, name, RRF_RT_REG_BINARY,
        nullptr, nullptr, &bytes);
    if (rc != ERROR_SUCCESS || bytes == 0 || bytes > 1024 * 1024)
        return false;
    value.resize(bytes);
    DWORD actual = bytes;
    rc = RegGetValueW(key, nullptr, name, RRF_RT_REG_BINARY,
        nullptr, value.data(), &actual);
    return rc == ERROR_SUCCESS && actual == bytes;
}

std::wstring RegistryEntryName(const PasswordEntry& entry)
{
    return std::to_wstring(entry.id) + L"_" + entry.name;
}

bool SaveEncryptedEntry(const PasswordEntry& entry,
    const std::array<BYTE, KEY_BYTES>& key)
{
    std::wstring valueName = RegistryEntryName(entry);
    std::vector<BYTE> record;
    if (!EncryptText(key, valueName, entry.password, record) ||
        record.size() > 1024 * 1024) return false;
    HKEY reg = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, ENCRYPTED_PATH, 0,
        nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
        nullptr, &reg, nullptr);
    if (rc != ERROR_SUCCESS) return false;
    bool ok = WriteBinaryValue(reg, valueName.c_str(), record);
    RegCloseKey(reg);
    return ok;
}

bool SaveKdfMetadata(const std::array<BYTE, SALT_BYTES>& salt)
{
    HKEY reg = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &reg, nullptr)
        != ERROR_SUCCESS) return false;
    const DWORD version = 1;
    bool ok = RegSetValueExW(reg, L"KdfSalt", 0, REG_BINARY,
        salt.data(), SALT_BYTES) == ERROR_SUCCESS &&
        RegSetValueExW(reg, L"KdfIterations", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&KDF_ITERATIONS),
            sizeof(KDF_ITERATIONS)) == ERROR_SUCCESS &&
        RegSetValueExW(reg, L"KdfVersion", 0, REG_DWORD,
            reinterpret_cast<const BYTE*>(&version), sizeof(version))
        == ERROR_SUCCESS;
    RegCloseKey(reg);
    return ok;
}

bool LoadKdfMetadata(std::array<BYTE, SALT_BYTES>& salt, DWORD& iterations)
{
    DWORD bytes = SALT_BYTES;
    LONG rc = RegGetValueW(HKEY_CURRENT_USER, REGISTRY_PATH,
        L"KdfSalt", RRF_RT_REG_BINARY, nullptr, salt.data(), &bytes);
    if (rc != ERROR_SUCCESS || bytes != SALT_BYTES) return false;
    bytes = sizeof(iterations);
    rc = RegGetValueW(HKEY_CURRENT_USER, REGISTRY_PATH,
        L"KdfIterations", RRF_RT_REG_DWORD, nullptr, &iterations, &bytes);
    if (rc != ERROR_SUCCESS || bytes != sizeof(iterations) ||
        iterations < 100000 || iterations > 10000000) return false;
    DWORD version = 0;
    bytes = sizeof(version);
    rc = RegGetValueW(HKEY_CURRENT_USER, REGISTRY_PATH,
        L"KdfVersion", RRF_RT_REG_DWORD, nullptr, &version, &bytes);
    return rc == ERROR_SUCCESS && bytes == sizeof(version) && version == 1;
}

bool SaveMasterCheck(const std::array<BYTE, KEY_BYTES>& key)
{
    std::vector<BYTE> record;
    if (!EncryptText(key, L"MasterCheck", L"PM-VAULT-V1", record)) return false;
    HKEY reg = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &reg, nullptr)
        != ERROR_SUCCESS) return false;
    bool ok = WriteBinaryValue(reg, L"MasterCheck", record);
    RegCloseKey(reg);
    return ok;
}

bool VerifyMasterCheck(const std::array<BYTE, KEY_BYTES>& key)
{
    HKEY reg = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0,
        KEY_READ, &reg) != ERROR_SUCCESS) return false;
    std::vector<BYTE> record;
    bool ok = ReadBinaryValue(reg, L"MasterCheck", record);
    RegCloseKey(reg);
    if (!ok) return false;
    std::wstring check;
    ok = DecryptText(key, L"MasterCheck", record, check) &&
        check == L"PM-VAULT-V1";
    WipeText(check);
    return ok;
}

// Stage encrypted entries BEFORE changing MasterPasswordEnabled to 1.
// If staging fails, legacy plaintext stays available for retry.
bool EnableEncryptionForExistingEntries(const std::wstring& password)
{
    std::array<BYTE, SALT_BYTES> salt{};
    std::array<BYTE, KEY_BYTES> key{};
    if (!GetRandomBytes(salt.data(), SALT_BYTES) ||
        !DeriveAesKey(password, salt, KDF_ITERATIONS, key)) return false;

    // Never delete existing encrypted data automatically.
    HKEY existing = nullptr;

    LONG checkRc = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        ENCRYPTED_PATH,
        0,
        KEY_READ,
        &existing
    );

    if (checkRc == ERROR_SUCCESS)
    {
        RegCloseKey(existing);
        WipeKey(key);
        return false;
    }

    if (checkRc != ERROR_FILE_NOT_FOUND &&
        checkRc != ERROR_PATH_NOT_FOUND)
    {
        WipeKey(key);
        return false;
    }

    bool ok = SaveKdfMetadata(salt) && SaveMasterCheck(key);
    if (ok)
    {
        // An empty vault still needs a real, existing encrypted subkey.
        HKEY reg = nullptr;
        ok = RegCreateKeyExW(HKEY_CURRENT_USER, ENCRYPTED_PATH, 0,
            nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
            nullptr, &reg, nullptr) == ERROR_SUCCESS;
        if (reg) RegCloseKey(reg);
    }
    for (const auto& entry : g_entries)
    {
        if (!ok) break;
        ok = SaveEncryptedEntry(entry, key);
    }
    WipeKey(key);
    if (!ok) return false;

    // Commit: the encrypted data will be used after this state change.
    return SaveMasterPasswordEnabled(true);
}

bool DeleteLegacyPlaintextEntries()
{
    bool ok = true;
    for (const auto& entry : g_entries)
    {
        // Error if any old plaintext cannot be removed.
        HKEY reg = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0,
            KEY_SET_VALUE, &reg);
        if (rc != ERROR_SUCCESS) { ok = false; continue; }
        std::wstring name = RegistryEntryName(entry);
        rc = RegDeleteValueW(reg, name.c_str());
        RegCloseKey(reg);
        if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) ok = false;
    }
    return ok;
}

bool LoadEncryptedEntries(const std::array<BYTE, KEY_BYTES>& key)
{
    HKEY reg = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, ENCRYPTED_PATH, 0,
        KEY_READ, &reg) != ERROR_SUCCESS) return false;

    DWORD maxNameLength = 0;
    if (RegQueryInfoKeyW(reg, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
        &maxNameLength, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
    {
        RegCloseKey(reg);
        return false;
    }
    std::vector<wchar_t> nameBuffer(static_cast<size_t>(maxNameLength) + 2);
    std::vector<PasswordEntry> loaded;
    unsigned int largestId = 0;
    bool ok = true;
    for (DWORD i = 0;; ++i)
    {
        DWORD length = static_cast<DWORD>(nameBuffer.size());
        LONG rc = RegEnumValueW(reg, i, nameBuffer.data(), &length,
            nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) { ok = false; break; }
        std::wstring valueName(nameBuffer.data(), length);
        size_t underscore = valueName.find(L'_');
        unsigned int id = 0;
        if (underscore == std::wstring::npos ||
            underscore + 1 >= valueName.size() ||
            !ParseEntryNumber(valueName.substr(0, underscore), id))
        {
            ok = false; break;
        }
        std::wstring name = valueName.substr(underscore + 1);
        std::vector<BYTE> record;
        std::wstring password;
        if (!ReadBinaryValue(reg, valueName.c_str(), record) ||
            !DecryptText(key, valueName, record, password))
        {
            ok = false; break;
        }
        loaded.push_back({ id, name, std::move(password) });
        if (id > largestId) largestId = id;
    }
    RegCloseKey(reg);
    if (ok)
    {
        std::sort(loaded.begin(), loaded.end(),
            [](const PasswordEntry& a, const PasswordEntry& b)
            { return a.id < b.id; });
        for (size_t i = 1; i < loaded.size(); ++i)
            if (loaded[i - 1].id == loaded[i].id) ok = false;
    }
    if (!ok)
    {
        for (auto& entry : loaded) WipeText(entry.password);
        return false;
    }
    g_entries = std::move(loaded);
    g_nextId = largestId + 1;
    return true;
}

bool DeleteEncryptedEntryFromRegistry(const PasswordEntry& entry)
{
    HKEY reg = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, ENCRYPTED_PATH, 0,
        KEY_SET_VALUE, &reg) != ERROR_SUCCESS) return false;
    std::wstring name = RegistryEntryName(entry);
    LONG rc = RegDeleteValueW(reg, name.c_str());
    RegCloseKey(reg);
    return rc == ERROR_SUCCESS;
}

// Prompt UI and operations use transient keys, wiped after each operation.
bool UnlockEncryptedStorage(const std::wstring& master)
{
    std::array<BYTE, SALT_BYTES> salt{};
    std::array<BYTE, KEY_BYTES> key{};
    DWORD iterations = 0;
    if (!LoadKdfMetadata(salt, iterations)) return false;
    if (!DeriveAesKey(master, salt, iterations, key)) return false;
    bool ok = VerifyMasterCheck(key) && LoadEncryptedEntries(key);
    WipeKey(key);
    return ok;
}

bool AddEncryptedPassword(const std::wstring& master,
    const PasswordEntry& entry)
{
    std::array<BYTE, SALT_BYTES> salt{};
    std::array<BYTE, KEY_BYTES> key{};
    DWORD iterations = 0;
    if (!LoadKdfMetadata(salt, iterations) ||
        !DeriveAesKey(master, salt, iterations, key)) return false;
    bool ok = VerifyMasterCheck(key) && SaveEncryptedEntry(entry, key);
    WipeKey(key);
    return ok;
}

// Refresh the password manager's visible list.
void RefreshListBox()
{
    SendMessageW(
        g_listBox,
        LB_RESETCONTENT,
        0, 0
    );

    for (const auto& entry : g_entries)
    {
        SendMessageW(
            g_listBox,
            LB_ADDSTRING,
            0,
            reinterpret_cast<LPARAM>(
                entry.name.c_str())
        );
    }
}

// 이 코드 모듈에 포함된 함수의 선언을 전달합니다:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
//마스터 암호용 추가
LRESULT CALLBACK MasterWndProc(
    HWND, UINT, WPARAM, LPARAM
);

void ShowMasterPasswordWindow(
    HWND parent,
    MasterMode mode
);
//마스터 암호용 끝
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);



    // 전역 문자열을 초기화합니다.
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_PASSWORDMANAGER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 애플리케이션 초기화를 수행합니다:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PASSWORDMANAGER));

    MSG msg;

    // 기본 메시지 루프입니다:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  함수: MyRegisterClass()
//
//  용도: 창 클래스를 등록합니다.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PASSWORDMANAGER));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_PASSWORDMANAGER);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   함수: InitInstance(HINSTANCE, int)
//
//   용도: 인스턴스 핸들을 저장하고 주 창을 만듭니다.
//
//   주석:이 함수를 통해 인스턴스 핸들을 전역 변수에 저장하고
//        주 프로그램 창을 만든 다음 표시합니다.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 인스턴스 핸들을 전역 변수에 저장합니다.

   HWND hWnd = CreateWindowW(
       szWindowClass,
       szTitle,
       WS_OVERLAPPEDWINDOW,
       CW_USEDEFAULT, 0,
       590, 540,
       nullptr, nullptr,
       hInstance, nullptr
   );

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  함수: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  용도: 주 창의 메시지를 처리합니다.
//
//  WM_COMMAND  - 애플리케이션 메뉴를 처리합니다.
//  WM_PAINT    - 주 창을 그립니다.
//  WM_DESTROY  - 종료 메시지를 게시하고 반환합니다.
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        CreateControl(
            hWnd, L"STATIC", L"Entry name",
            0, 0, 20, 18, 245, 20, 0
        );

        CreateControl(
            hWnd, L"STATIC", L"Password",
            0, 0, 285, 18, 245, 20, 0
        );

        g_nameEdit = CreateControl(
            hWnd, L"EDIT", L"",
            WS_TABSTOP | ES_AUTOHSCROLL,
            WS_EX_CLIENTEDGE,
            20, 43, 245, 28, ID_PM_NAME
        );

        g_passwordEdit = CreateControl(
            hWnd, L"EDIT", L"",
            WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            WS_EX_CLIENTEDGE,
            285, 43, 245, 28, ID_PM_PASSWORD
        );

        CreateControl(
            hWnd, L"BUTTON", L"Add",
            WS_TABSTOP | BS_PUSHBUTTON,
            0, 20, 95, 110, 32, ID_PM_ADD
        );

        CreateControl(
            hWnd, L"BUTTON", L"Load",
            WS_TABSTOP | BS_PUSHBUTTON,
            0, 145, 95, 110, 32, ID_PM_LOAD
        );

        CreateControl(
            hWnd, L"BUTTON", L"Delete",
            WS_TABSTOP | BS_PUSHBUTTON,
            0, 270, 95, 110, 32, ID_PM_DELETE
        );

        CreateControl(
            hWnd, L"BUTTON", L"Show/Hide",
            WS_TABSTOP | BS_PUSHBUTTON,
            0, 395, 95, 135, 32, ID_PM_SHOW
        );

        // ===== 마스터 암호 설정 버튼 추가 시작 =====
        CreateControl(
            hWnd,
            L"BUTTON",
            L"마스터 암호 설정",
            WS_TABSTOP | BS_PUSHBUTTON,
            0,
            20, 403, 175, 32,
            ID_PM_MASTER
        );
        // ===== 마스터 암호 설정 버튼 추가 끝 =====



        g_listBox = CreateControl(
            hWnd, L"LISTBOX", L"",
            WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY,
            WS_EX_CLIENTEDGE,
            20, 145, 510, 220, ID_PM_LIST
        );

        g_statusLabel = CreateControl(
            hWnd,
            L"STATIC",
            L"Demo - Registry HEX storage. Not encrypted.",
            0, 0, 20, 449, 510, 20, 0
        );

        // Check the registry state BEFORE loading passwords.
        bool enabled = false;

        if (!LoadMasterPasswordEnabled(enabled))
        {
            MessageBoxW(
                hWnd,
                L"마스터 암호 설정 상태를 읽을 수 없습니다.",
                L"Error",
                MB_OK | MB_ICONERROR
            );

            EnableWindow(GetDlgItem(hWnd, ID_PM_MASTER), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_ADD), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_LOAD), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_DELETE), FALSE);

            return 0;
        }

        g_masterEnabled = enabled;

        SetWindowTextW(
            g_statusLabel,
            enabled
            ? L"Encrypted: AES-256-GCM / PBKDF2-HMAC-SHA256"
            : L"Demo - Registry HEX storage. Not encrypted."
        );

        SetWindowTextW(
            GetDlgItem(hWnd, ID_PM_MASTER),
            enabled
            ? L"마스터 암호 변경"
            : L"마스터 암호 설정"
        );

        if (enabled)
        {
            EnableWindow(GetDlgItem(hWnd, ID_PM_ADD), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_LOAD), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_DELETE), FALSE);

            PostMessageW(hWnd, WM_PM_UNLOCK, 0, 0);
        }
        else if (LoadEntriesFromRegistry())
        {
            g_storageReady = true;
            RefreshListBox();
        }
        else
        {
            MessageBoxW(
                hWnd,
                L"레지스트리 평문 목록을 읽지 못했습니다.\n"
                L"기존 데이터를 보호하기 위해 Add와 Delete를 비활성화합니다.",
                L"Error",
                MB_OK | MB_ICONERROR
            );

            EnableWindow(GetDlgItem(hWnd, ID_PM_MASTER), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_ADD), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_LOAD), FALSE);
            EnableWindow(GetDlgItem(hWnd, ID_PM_DELETE), FALSE);
        }

        return 0;
    }
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        // 메뉴 선택을 구문 분석합니다:
        switch (wmId)
        {
            // ===== 마스터 암호 설정 버튼 이벤트 시작 =====
        case ID_PM_MASTER:
        {
            if (!g_storageReady)
                break;

            if (g_masterEnabled)
            {
                MessageBoxW(
                    hWnd,
                    L"현재 버전은 마스터 암호 변경 기능을 지원하지 않습니다.\n"
                    L"기존 암호화 데이터를 보호하기 위해 변경을 진행하지 않습니다.",
                    L"안내",
                    MB_OK | MB_ICONINFORMATION
                );
            }
            else
            {
                ShowMasterPasswordWindow(
                    hWnd,
                    MasterMode::Setup
                );
            }

            break;
        }
        // ===== 마스터 암호 설정 버튼 이벤트 끝 =====

                // Add a password
        case ID_PM_ADD:
        {
            if (!g_storageReady)
                break;

            std::wstring name =
                ReadControlText(g_nameEdit);

            std::wstring password =
                ReadControlText(g_passwordEdit);

            if (name.empty() || password.empty())
            {
                MessageBoxW(
                    hWnd,
                    L"Please enter a name and password.",
                    L"Warning",
                    MB_OK | MB_ICONWARNING
                );

                WipeText(password);
                break;
            }

            if (g_nextId == 0)
            {
                WipeText(password);
                break;
            }

            if (g_masterEnabled)
            {
                // Master password authentication required.
                WipeText(password);

                ShowMasterPasswordWindow(
                    hWnd,
                    MasterMode::EncryptAdd
                );

                break;
            }

            // Plaintext mode.
            if (!SaveEntryToRegistry(
                g_nextId,
                name,
                password))
            {
                MessageBoxW(
                    hWnd,
                    L"레지스트리에 비밀번호를 저장하지 못했습니다.",
                    L"Error",
                    MB_OK | MB_ICONERROR
                );

                WipeText(password);
                break;
            }

            g_entries.push_back({
                g_nextId, name, password
                });

            WipeText(password);

            ++g_nextId;

            RefreshListBox();

            SetWindowTextW(g_nameEdit, L"");
            SetWindowTextW(g_passwordEdit, L"");

            break;
        }

            // Load the selected password
            case ID_PM_LOAD:
            {
                LRESULT index = SendMessageW(
                    g_listBox, LB_GETCURSEL, 0, 0
                );

                if (index == LB_ERR)
                {
                    MessageBoxW(
                        hWnd, L"Select an entry first.",
                        L"Information", MB_OK
                    );
                    break;
                }

                const PasswordEntry& entry = g_entries[index];

                SetWindowTextW(g_nameEdit, entry.name.c_str());
                SetWindowTextW(g_passwordEdit, entry.password.c_str());
                break;
            }

            // Delete the selected password
            case ID_PM_DELETE:
            {
                LRESULT index = SendMessageW(
                    g_listBox, LB_GETCURSEL, 0, 0
                );

                if (index == LB_ERR)
                {
                    MessageBoxW(
                        hWnd, L"Select an entry first.",
                        L"Information", MB_OK
                    );
                    break;
                }

                // Delete from the appropriate registry location.
                bool removed = g_masterEnabled
                    ? DeleteEncryptedEntryFromRegistry(g_entries[index])
                    : DeleteEntryFromRegistry(g_entries[index]);

                if (!removed)
                {
                    MessageBoxW(
                        hWnd,
                        L"레지스트리에서 비밀번호를 삭제하지 못했습니다.",
                        L"Error",
                        MB_OK | MB_ICONERROR
                    );
                    break;
                }

                WipeText(g_entries[index].password);

                g_entries.erase(g_entries.begin() + index);

                RefreshListBox();

                SetWindowTextW(g_nameEdit, L"");
                SetWindowTextW(g_passwordEdit, L"");
                break;
            }

            // Show or hide the password
            case ID_PM_SHOW:
            {
                g_showPassword = !g_showPassword;

                SendMessageW(
                    g_passwordEdit,
                    EM_SETPASSWORDCHAR,
                    g_showPassword ? 0 : L'*',
                    0
                );

                InvalidateRect(g_passwordEdit, nullptr, TRUE);
                break;
            }
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;

    case WM_PM_UNLOCK:
    {
        if (g_masterEnabled && !g_storageReady)
        {
            ShowMasterPasswordWindow(
                hWnd,
                MasterMode::Unlock
            );
        }

        return 0;
    }
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: 여기에 hdc를 사용하는 그리기 코드를 추가합니다...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
    {
        for (auto& entry : g_entries)
        {
            WipeText(entry.password);
        }

        g_entries.clear();

        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// 정보 대화 상자의 메시지 처리기입니다.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
void ShowMasterPasswordWindow(
    HWND parent,
    MasterMode mode)
{
    // Prevent duplicate windows
    if (g_masterWindow != nullptr)
    {
        SetForegroundWindow(g_masterWindow);
        return;
    }

    g_masterMode = mode;

    const wchar_t CLASS_NAME[] =
        L"MasterPasswordWindowClass";

    static bool registered = false;

    if (!registered)
    {
        WNDCLASSW wc = {};

        wc.lpfnWndProc = MasterWndProc;
        wc.hInstance = hInst;
        wc.lpszClassName = CLASS_NAME;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);

        if (!RegisterClassW(&wc))
        {
            MessageBoxW(
                parent,
                L"창 클래스를 등록하지 못했습니다.",
                L"Error",
                MB_OK | MB_ICONERROR
            );
            return;
        }

        registered = true;
    }

    // Center the new window over the main window
    RECT parentRect;
    GetWindowRect(parent, &parentRect);

    int width = 460;
    int height = 350;

    int x = parentRect.left +
        ((parentRect.right - parentRect.left) - width) / 2;

    int y = parentRect.top +
        ((parentRect.bottom - parentRect.top) - height) / 2;

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        mode == MasterMode::Setup
        ? L"마스터 암호 설정"
        : mode == MasterMode::Unlock
        ? L"암호 관리자 잠금 해제"
        : L"비밀번호 저장 인증",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        x, y,
        width, height,
        parent,
        nullptr,
        hInst,
        nullptr
    );

    if (!window)
    {
        MessageBoxW(
            parent,
            L"마스터 암호 설정 창을 생성하지 못했습니다.",
            L"Error",
            MB_OK | MB_ICONERROR
        );
        return;
    }

    g_masterWindow = window;

    // Disable the main window while settings are open
    EnableWindow(parent, FALSE);

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    SetForegroundWindow(window);
    SetFocus(g_masterInput);
}
LRESULT CALLBACK MasterWndProc(
    HWND hWnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam
)
{
    switch (message)
    {
    case WM_CREATE:
    {
        CreateControl(
            hWnd, L"STATIC",
            g_masterMode == MasterMode::Setup
            ? L"암호 관리자에 사용할 마스터 암호를 입력하세요."
            : L"기존 마스터 암호를 입력하세요.",
            0, 0, 20, 20, 410, 20, 0
        );

        CreateControl(
            hWnd, L"STATIC",
            g_masterMode == MasterMode::Setup
            ? L"마스터 암호는 8자 이상이어야 합니다."
            : L"입력한 마스터 암호는 저장하지 않습니다.",
            0, 0, 20, 42, 410, 20, 0
        );

        CreateControl(
            hWnd, L"STATIC", L"",
            SS_ETCHEDHORZ, 0,
            20, 70, 410, 2, 0
        );

        CreateControl(
            hWnd, L"STATIC", L"암호 입력",
            0, 0, 20, 88, 410, 20, 0
        );

        g_masterInput = CreateControl(
            hWnd, L"EDIT", L"",
            WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            WS_EX_CLIENTEDGE,
            20, 110, 410, 28,
            ID_MASTER_INPUT
        );

        HWND confirmLabel = CreateControl(
            hWnd, L"STATIC", L"암호 확인",
            0, 0, 20, 145, 410, 20, 0
        );

        g_masterConfirm = CreateControl(
            hWnd, L"EDIT", L"",
            WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            WS_EX_CLIENTEDGE,
            20, 167, 410, 28,
            ID_MASTER_CONFIRM
        );

        CreateControl(
            hWnd, L"BUTTON", L"암호 보이기",
            WS_TABSTOP | BS_AUTOCHECKBOX,
            0,
            20, 210, 150, 25,
            ID_MASTER_SHOW
        );

        g_masterOk = CreateControl(
            hWnd, L"BUTTON", L"확인",
            WS_TABSTOP | BS_DEFPUSHBUTTON,
            0,
            265, 265, 75, 30,
            ID_MASTER_OK
        );

        CreateControl(
            hWnd, L"BUTTON", L"취소",
            WS_TABSTOP | BS_PUSHBUTTON,
            0,
            350, 265, 80, 30,
            ID_MASTER_CANCEL
        );

        if (g_masterMode != MasterMode::Setup)
        {
            ShowWindow(confirmLabel, SW_HIDE);
            ShowWindow(g_masterConfirm, SW_HIDE);
        }

        // Initially disable OK
        EnableWindow(g_masterOk, FALSE);

        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        int notification = HIWORD(wParam);

        switch (id)
        {
            // Validate both input fields
        case ID_MASTER_INPUT:
        case ID_MASTER_CONFIRM:
        {
            if (notification == EN_CHANGE)
            {
                std::wstring password =
                    ReadControlText(g_masterInput);

                std::wstring confirm =
                    ReadControlText(g_masterConfirm);

                bool valid =
                    g_masterMode == MasterMode::Setup
                    ? password.length() >= 8 &&
                    password == confirm
                    : !password.empty();

                EnableWindow(
                    g_masterOk,
                    valid ? TRUE : FALSE
                );

                WipeText(password);
                WipeText(confirm);
            }

            return 0;
        }

        // Toggle password visibility
        case ID_MASTER_SHOW:
        {
            if (notification == BN_CLICKED)
            {
                bool show =
                    SendMessageW(
                        GetDlgItem(hWnd, ID_MASTER_SHOW),
                        BM_GETCHECK, 0, 0
                    ) == BST_CHECKED;

                SendMessageW(
                    g_masterInput,
                    EM_SETPASSWORDCHAR,
                    show ? 0 : L'*',
                    0
                );

                SendMessageW(
                    g_masterConfirm,
                    EM_SETPASSWORDCHAR,
                    show ? 0 : L'*',
                    0
                );

                InvalidateRect(
                    g_masterInput, nullptr, TRUE
                );

                InvalidateRect(
                    g_masterConfirm, nullptr, TRUE
                );
            }

            return 0;
        }

        // Confirm password
        case ID_MASTER_OK:
        {
            std::wstring password =
                ReadControlText(g_masterInput);

            std::wstring confirm;

            if (g_masterMode == MasterMode::Setup)
            {
                confirm = ReadControlText(g_masterConfirm);
            }

            if (g_masterMode == MasterMode::Setup &&
                (password.length() < 8 || password != confirm))
            {
                WipeText(password);
                WipeText(confirm);

                MessageBoxW(
                    hWnd,
                    L"마스터 암호는 8자 이상이며 두 입력값이 같아야 합니다.",
                    L"경고",
                    MB_OK | MB_ICONWARNING
                );

                return 0;
            }

            HWND owner = GetWindow(hWnd, GW_OWNER);
            bool success = false;

            // 1. Master password setup.
            if (g_masterMode == MasterMode::Setup)
            {
                success =
                    EnableEncryptionForExistingEntries(password);

                if (success)
                {
                    g_masterEnabled = true;

                    SetWindowTextW(
                        g_statusLabel,
                        L"Encrypted: AES-256-GCM / PBKDF2-HMAC-SHA256"
                    );

                    SetWindowTextW(
                        GetDlgItem(owner, ID_PM_MASTER),
                        L"마스터 암호 변경"
                    );
                }
            }

            // 2. Unlock encrypted storage.
            else if (g_masterMode == MasterMode::Unlock)
            {
                success = UnlockEncryptedStorage(password);

                if (success)
                {
                    g_storageReady = true;

                    RefreshListBox();

                    EnableWindow(
                        GetDlgItem(owner, ID_PM_ADD), TRUE
                    );

                    EnableWindow(
                        GetDlgItem(owner, ID_PM_LOAD), TRUE
                    );

                    EnableWindow(
                        GetDlgItem(owner, ID_PM_DELETE), TRUE
                    );
                }
            }

            // 3. Add a new encrypted password.
            else if (g_masterMode == MasterMode::EncryptAdd)
            {
                std::wstring name =
                    ReadControlText(g_nameEdit);

                std::wstring entryPassword =
                    ReadControlText(g_passwordEdit);

                if (g_storageReady &&
                    g_nextId != 0 &&
                    !name.empty() &&
                    !entryPassword.empty())
                {
                    PasswordEntry entry{
                        g_nextId,
                        name,
                        entryPassword
                    };

                    success =
                        AddEncryptedPassword(password, entry);

                    if (success)
                    {
                        g_entries.push_back(std::move(entry));

                        ++g_nextId;

                        RefreshListBox();

                        SetWindowTextW(g_nameEdit, L"");
                        SetWindowTextW(g_passwordEdit, L"");
                    }
                    else
                    {
                        WipeText(entry.password);
                    }
                }

                WipeText(entryPassword);
            }

            // Clear temporary master password buffers.
            WipeText(password);
            WipeText(confirm);

            SetWindowTextW(g_masterInput, L"");
            SetWindowTextW(g_masterConfirm, L"");

            if (!success)
            {
                MessageBoxW(
                    hWnd,
                    L"암호 확인 또는 레지스트리 처리에 실패했습니다.\n"
                    L"기존 데이터를 보호하기 위해 작업을 중단합니다.",
                    L"Error",
                    MB_OK | MB_ICONERROR
                );

                return 0;
            }

            MasterMode completedMode = g_masterMode;

            DestroyWindow(hWnd);

            // Remove old plaintext registry entries.
            if (completedMode == MasterMode::Setup ||
                completedMode == MasterMode::Unlock)
            {
                if (!DeleteLegacyPlaintextEntries())
                {
                    MessageBoxW(
                        owner,
                        L"암호화된 데이터는 저장되었지만 기존 평문 항목 일부를\n"
                        L"레지스트리에서 삭제하지 못했습니다. 추가 확인이 필요합니다.",
                        L"Warning",
                        MB_OK | MB_ICONWARNING
                    );
                }
            }

            return 0;
        }

        // Cancel
        case ID_MASTER_CANCEL:
        {
            DestroyWindow(hWnd);
            return 0;
        }
        }

        break;
    }

    case WM_CLOSE:
    {
        DestroyWindow(hWnd);
        return 0;
    }

    case WM_DESTROY:
    {
        HWND owner = GetWindow(hWnd, GW_OWNER);

        g_masterWindow = nullptr;
        g_masterInput = nullptr;
        g_masterConfirm = nullptr;
        g_masterOk = nullptr;

        if (owner)
        {
            EnableWindow(owner, TRUE);

            if (g_masterMode == MasterMode::Unlock &&
                !g_storageReady)
            {
                DestroyWindow(owner);
            }
            else
            {
                SetForegroundWindow(owner);
                SetActiveWindow(owner);
            }
        }

        return 0;
    }
    }

    return DefWindowProcW(
        hWnd, message, wParam, lParam
    );
}