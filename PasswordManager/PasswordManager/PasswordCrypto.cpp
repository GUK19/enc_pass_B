// PasswordCrypto.cpp : 마스터 암호 기반 키 유도, 암호화 및 암호화 저장소 관리.
#include "framework.h"
#include "PasswordCrypto.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <array>
#include <cstring>
#include <bcrypt.h>

#include <ktmw32.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "KtmW32.lib")

// Encrypted records live in a separate registry subkey.
// [암호문 저장 위치] EncryptedEntries는 REGISTRY_PATH의 하위 키이다.
// 암호화 모드의 각 비밀번호는 "ID_항목명"에 REG_BINARY로 저장된다.
// 이 경로에 저장된 항목 데이터가 AES-GCM 암호문이다.


constexpr wchar_t ENCRYPTED_PATH[] =
L"Software\\enc_pass_B\\PasswordManager\\EncryptedEntries";
// 마스터 암호를 설정하는 순간 비밀번호들은 AES-256-GCM으로 암호화하여 저장한다.
//
// 암호화된 비밀번호는 REGISTRY_PATH에 직접 저장하지 않고,
// 그 하위 폴더 EncryptedEntries라는 별도의 공간을 만들어 저장한다.
//
// 예를 들어 GitHub라는 이름으로 비밀번호를 등록했다면,
// EncryptedEntries 안에 "1_GitHub"라는 이름의 레지스트리 값이 생길 수 있다. -> update 필요
// "1_GitHub"는 항목을 구분하기 위한 이름이고,
// 그 값의 데이터 부분에는 암호화된 비밀번호가 저장된다.
//
//
// 참고로 레지스트리의 REG_BINARY는 데이터를 바이트 단위로 저장하는 형식이다.
// 이 프로그램은 암호화된 데이터를 REG_BINARY 형식으로 저장한다.


// 암호화에 사용할 키, Salt, Nonce, 인증 태그의 길이를 바이트 단위로 정합니다.
// 32바이트는 256비트이며, AES-256의 키 크기에 해당합니다.
constexpr ULONG KEY_BYTES = 32;
constexpr ULONG SALT_BYTES = 16;
constexpr ULONG NONCE_BYTES = 12;
constexpr ULONG TAG_BYTES = 16;

constexpr DWORD KDF_ITERATIONS = 600000; // PBKDF2를 반복할 횟수입니다. 키를 처음 만들 때와 다시 만들 때 모두 사용합니다.

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

// Save master password setup status (0 or 1).
// 마스터 암호 설정 여부를 MasterPasswordEnabled라는 이름으로 저장합니다.
// enabled가 true이면 1, false이면 0을 기록합니다.
static bool SaveMasterPasswordEnabled(bool enabled)
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

// PBKDF2로 만든 32바이트 대칭키 배열을 0으로 덮습니다.
static void WipeKey(std::array<BYTE, KEY_BYTES>& key)
{
    SecureZeroMemory(key.data(), key.size());
}

// Windows의 난수 생성 기능으로 size바이트를 만들어 output에 채웁니다.
// Salt와 암호화할 때마다 새로 필요한 Nonce를 만드는 데 사용합니다.
static bool GetRandomBytes(BYTE* output, ULONG size)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, output, size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// 마스터 암호(password), Salt, 반복 횟수로 AES-256 키를 만듭니다.
// PBKDF2-HMAC-SHA256을 사용하며 생성된 32바이트 키를 output에 기록합니다.
// 같은 입력값을 넣으면 같은 키가 만들어집니다.
static bool DeriveAesKey(const std::wstring& password,
    const std::array<BYTE, SALT_BYTES>& salt, DWORD iterations,
    std::array<BYTE, KEY_BYTES>& output)
{
    if (password.empty() || iterations < 100000 || iterations > 10000000 ||
        password.size() > (std::numeric_limits<ULONG>::max)() / sizeof(wchar_t))
        return false;

    // HMAC-SHA256 알고리즘을 열고 PBKDF2로 키를 유도합니다.
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
// AES-256-GCM 방식으로 바이트 데이터를 암호화하거나 복호화합니다.
// encrypt가 true이면 암호화, false이면 복호화합니다.
// valueName은 데이터의 이름을 인증에 포함하며, 복호화 시 인증이 실패하면 false입니다.
static bool AesGcmTransform(bool encrypt,
    const std::array<BYTE, KEY_BYTES>& rawKey,
    const std::wstring& valueName,
    const std::vector<BYTE>& input,
    const BYTE* nonce, BYTE* tag,
    std::vector<BYTE>& output,
    bool* authenticationRejected = nullptr)
{
    if (authenticationRejected)
        *authenticationRejected = false;

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
        // ===== AES-GCM 인증 실패 확인 시작 =====
        constexpr NTSTATUS AUTH_TAG_MISMATCH_STATUS =
            static_cast<NTSTATUS>(0xC000A002u);

        if (!encrypt &&
            authenticationRejected &&
            status == AUTH_TAG_MISMATCH_STATUS)
        {
            *authenticationRejected = true;
        }
        // ===== AES-GCM 인증 실패 확인 끝 =====
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



// 
// 비밀번호를 AES-256-GCM으로 암호화합니다.
// 암호화할 때마다 새로운 무작위 값(Nonce)을 생성하며,
// 암호문이 변조되지 않았는지 확인할 인증 태그도 함께 생성합니다.
// 결과는 [식별표시(PM01), Nonce, 인증 태그, 암호문] 순서로 저장합니다.
static bool EncryptText(const std::array<BYTE, KEY_BYTES>& key,
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

static bool DecryptText(const std::array<BYTE, KEY_BYTES>& key,
    const std::wstring& valueName, const std::vector<BYTE>& record,
    std::wstring& plain,
    bool* authenticationRejected = nullptr)
{
    if (authenticationRejected)
        *authenticationRejected = false;

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
        nonce, tag.data(), decoded, authenticationRejected);
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

static bool WriteBinaryValue(HKEY key, const wchar_t* name,
    const std::vector<BYTE>& value)
{
    if (value.size() > (std::numeric_limits<DWORD>::max)()) return false;
    return RegSetValueExW(key, name, 0, REG_BINARY, value.data(),
        static_cast<DWORD>(value.size())) == ERROR_SUCCESS;
}

static bool ReadBinaryValue(HKEY key, const wchar_t* name,
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

static std::wstring RegistryEntryName(const PasswordEntry& entry)
{
    return std::to_wstring(entry.id) + L"_" + entry.name;
}

static bool SaveEncryptedEntry(const PasswordEntry& entry,
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

static bool SaveKdfMetadata(const std::array<BYTE, SALT_BYTES>& salt)
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

static bool LoadKdfMetadata(std::array<BYTE, SALT_BYTES>& salt, DWORD& iterations)
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

static bool SaveMasterCheck(const std::array<BYTE, KEY_BYTES>& key)
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

static bool VerifyMasterCheck(const std::array<BYTE, KEY_BYTES>& key,
    bool* masterCheckRejected)
{
    if (masterCheckRejected)
        *masterCheckRejected = false;

    HKEY reg = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REGISTRY_PATH, 0,
        KEY_READ, &reg) != ERROR_SUCCESS) return false;
    std::vector<BYTE> record;
    bool ok = ReadBinaryValue(reg, L"MasterCheck", record);
    RegCloseKey(reg);
    if (!ok) return false;
    std::wstring check;
    ok = DecryptText(key, L"MasterCheck", record, check,
        masterCheckRejected) &&
        check == L"PM-VAULT-V1";
    WipeText(check);
    return ok;
}

// Stage encrypted entries BEFORE changing MasterPasswordEnabled to 1.
// If staging fails, legacy plaintext stays available for retry.
bool EnableEncryptionForExistingEntries(const std::wstring& password,
    const std::vector<PasswordEntry>& entries)
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
    for (const auto& entry : entries)
    {
        if (!ok) break;
        ok = SaveEncryptedEntry(entry, key);
    }
    WipeKey(key);
    if (!ok) return false;

    // Commit: the encrypted data will be used after this state change.
    return SaveMasterPasswordEnabled(true);
}

bool DeleteLegacyPlaintextEntries(const std::vector<PasswordEntry>& entries)
{
    bool ok = true;
    for (const auto& entry : entries)
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

static bool LoadEncryptedEntries(const std::array<BYTE, KEY_BYTES>& key,
    std::vector<PasswordEntry>& entries, unsigned int& nextId)
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
    entries = std::move(loaded);
    nextId = largestId + 1;
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
bool UnlockEncryptedStorage(const std::wstring& master,
    std::vector<PasswordEntry>& entries, unsigned int& nextId,
    bool* masterCheckRejected)
{
    if (masterCheckRejected)
        *masterCheckRejected = false;

    std::array<BYTE, SALT_BYTES> salt{};
    std::array<BYTE, KEY_BYTES> key{};
    DWORD iterations = 0;
    if (!LoadKdfMetadata(salt, iterations)) return false;
    if (!DeriveAesKey(master, salt, iterations, key)) return false;
    bool ok = VerifyMasterCheck(key, masterCheckRejected) &&
        LoadEncryptedEntries(key, entries, nextId);
    WipeKey(key);
    return ok;
}

bool AddEncryptedPassword(const std::wstring& master,
    const PasswordEntry& entry,
    bool* masterCheckRejected)
{
    if (masterCheckRejected)
        *masterCheckRejected = false;

    std::array<BYTE, SALT_BYTES> salt{};
    std::array<BYTE, KEY_BYTES> key{};
    DWORD iterations = 0;
    if (!LoadKdfMetadata(salt, iterations) ||
        !DeriveAesKey(master, salt, iterations, key)) return false;
    bool ok = VerifyMasterCheck(key, masterCheckRejected) &&
        SaveEncryptedEntry(entry, key);
    WipeKey(key);
    return ok;
}



// 평문 저장이 완료된 후 암호화 모드를 해제하고
// 더 이상 필요하지 않은 암호화 관련 데이터를 삭제합니다.
bool FinishMasterPasswordRemoval(bool& cleanupOk)
{
    cleanupOk = true;

    HKEY reg = nullptr;

    LONG rc = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        0,
        DELETE | KEY_ENUMERATE_SUB_KEYS |
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        &reg
    );

    if (rc != ERROR_SUCCESS)
        return false;

    // 1. 마스터 암호 설정 상태를 0으로 변경합니다.
    if (!SaveMasterPasswordEnabled(false))
    {
        RegCloseKey(reg);
        return false;
    }

    // 평문 데이터와 변경된 설정 상태를 디스크에 반영합니다.
    // 실패하면 기존 암호화 데이터는 삭제하지 않습니다.
    if (RegFlushKey(reg) != ERROR_SUCCESS)
    {
        cleanupOk = false;
        RegCloseKey(reg);
        return true;
    }

    // 2. 기존 암호화된 비밀번호 저장 공간을 삭제합니다.
    rc = RegDeleteTreeW(reg, L"EncryptedEntries");

    cleanupOk =
        rc == ERROR_SUCCESS ||
        rc == ERROR_FILE_NOT_FOUND ||
        rc == ERROR_PATH_NOT_FOUND;

    // 3. 암호화 저장소가 제거된 경우 KDF 정보와
    //    마스터 암호 검증용 데이터를 삭제합니다.
    if (cleanupOk)
    {
        const wchar_t* valuesToDelete[] =
        {
            L"KdfVersion",
            L"KdfSalt",
            L"KdfIterations",
            L"MasterCheck"
        };

        for (const wchar_t* valueName : valuesToDelete)
        {
            rc = RegDeleteValueW(reg, valueName);

            if (rc != ERROR_SUCCESS &&
                rc != ERROR_FILE_NOT_FOUND)
            {
                cleanupOk = false;
            }
        }
    }

    RegCloseKey(reg);

    return true;
}

// 암호관리자의 모든 저장 데이터를 삭제하고
// 마스터 암호가 설정되지 않은 상태로 초기화합니다.
bool ResetPasswordManagerStorage()
{
    bool enabled = false;

    if (!LoadMasterPasswordEnabled(enabled) || !enabled)
        return false;

    HKEY reg = nullptr;

    LONG rc = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        REGISTRY_PATH,
        0,
        DELETE | KEY_ENUMERATE_SUB_KEYS |
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        &reg
    );

    if (rc != ERROR_SUCCESS)
        return false;

    // 1. EncryptedEntries를 포함한 모든 하위 키 삭제.
    for (;;)
    {
        wchar_t subKeyName[256] = {};
        DWORD length = 256;

        rc = RegEnumKeyExW(
            reg,
            0,
            subKeyName,
            &length,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );

        if (rc == ERROR_NO_MORE_ITEMS)
            break;

        if (rc != ERROR_SUCCESS)
        {
            RegCloseKey(reg);
            return false;
        }

        rc = RegDeleteTreeW(reg, subKeyName);

        if (rc != ERROR_SUCCESS)
        {
            RegCloseKey(reg);
            return false;
        }
    }

    // 2. 레지스트리 값 이름의 최대 길이 확인.
    DWORD maxValueNameLength = 0;

    rc = RegQueryInfoKeyW(
        reg,
        nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr,
        nullptr,
        &maxValueNameLength,
        nullptr, nullptr, nullptr
    );

    if (rc != ERROR_SUCCESS)
    {
        RegCloseKey(reg);
        return false;
    }

    std::vector<wchar_t> valueName(
        static_cast<size_t>(maxValueNameLength) + 1
    );

    // 3. MasterPasswordEnabled를 제외한 모든 값 삭제.
    DWORD index = 0;

    for (;;)
    {
        DWORD length =
            static_cast<DWORD>(valueName.size());

        rc = RegEnumValueW(
            reg,
            index,
            valueName.data(),
            &length,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );

        if (rc == ERROR_NO_MORE_ITEMS)
            break;

        if (rc != ERROR_SUCCESS)
        {
            RegCloseKey(reg);
            return false;
        }

        // 초기화가 완료되기 전까지 설정 상태를 유지합니다.
        if (CompareStringOrdinal(
            valueName.data(), -1,
            L"MasterPasswordEnabled", -1,
            TRUE) == CSTR_EQUAL)
        {
            ++index;
            continue;
        }

        rc = RegDeleteValueW(
            reg,
            valueName.data()
        );

        if (rc != ERROR_SUCCESS)
        {
            RegCloseKey(reg);
            return false;
        }
    }

    // 4. 삭제 결과를 디스크에 반영합니다.
    rc = RegFlushKey(reg);

    RegCloseKey(reg);

    if (rc != ERROR_SUCCESS)
        return false;

    // 5. 모든 삭제가 완료된 후 설정 상태를 0으로 변경.
    return SaveMasterPasswordEnabled(false);
}

// 기존 마스터 암호를 검증한 후 모든 비밀번호를
// 새로운 마스터 암호 기반의 키로 다시 암호화합니다.
//
// 일반 비밀번호를 평문 상태로 레지스트리에 저장하지 않습니다.
// 모든 레지스트리 변경 작업은 하나의 트랜잭션으로 처리합니다.
bool ChangeMasterPassword(
    const std::wstring& oldMaster,
    const std::wstring& newMaster)
{
    // 1. 마스터 암호 설정 상태 및 새로운 암호 확인.
    bool enabled = false;

    if (!LoadMasterPasswordEnabled(enabled) ||
        !enabled ||
        oldMaster.empty() ||
        newMaster.length() < 8)
    {
        return false;
    }

    // 2. 기존 마스터 암호 검증 및 전체 비밀번호 복호화.
    std::vector<PasswordEntry> restored;
    unsigned int nextId = 1;

    if (!UnlockEncryptedStorage(
        oldMaster, restored, nextId))
    {
        return false;
    }

    // 3. 새로운 Salt와 AES-256 키를 위한 변수.
    std::array<BYTE, SALT_BYTES> newSalt{};
    std::array<BYTE, KEY_BYTES> newKey{};

    HANDLE transaction = INVALID_HANDLE_VALUE;

    HKEY reg = nullptr;
    HKEY encryptedReg = nullptr;

    bool ok = false;

    do
    {
        // 4. 새로운 Salt 및 암호화 키 생성.
        if (!GetRandomBytes(
            newSalt.data(), SALT_BYTES) ||
            !DeriveAesKey(
                newMaster,
                newSalt,
                KDF_ITERATIONS,
                newKey))
        {
            break;
        }

        // 5. 레지스트리 트랜잭션 생성.
        transaction = CreateTransaction(
            nullptr,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr
        );

        if (transaction == INVALID_HANDLE_VALUE)
            break;

        // 6. KDF 정보와 MasterCheck가 저장되는 키 열기.
        if (RegOpenKeyTransactedW(
            HKEY_CURRENT_USER,
            REGISTRY_PATH,
            0,
            KEY_SET_VALUE,
            &reg,
            transaction,
            nullptr) != ERROR_SUCCESS)
        {
            break;
        }

        // 7. 암호화된 일반 비밀번호 저장 공간 열기.
        if (RegOpenKeyTransactedW(
            HKEY_CURRENT_USER,
            ENCRYPTED_PATH,
            0,
            KEY_SET_VALUE,
            &encryptedReg,
            transaction,
            nullptr) != ERROR_SUCCESS)
        {
            break;
        }

        // 8. 모든 일반 비밀번호를 새로운 키로 암호화.
        bool entriesOk = true;

        for (const auto& entry : restored)
        {
            std::wstring valueName =
                RegistryEntryName(entry);

            std::vector<BYTE> record;

            if (!EncryptText(
                newKey,
                valueName,
                entry.password,
                record) ||
                record.size() > 1024 * 1024 ||
                !WriteBinaryValue(
                    encryptedReg,
                    valueName.c_str(),
                    record))
            {
                entriesOk = false;
                break;
            }
        }

        if (!entriesOk)
            break;

        // 9. 새로운 KDF 설정값 저장.
        const DWORD version = 1;

        if (RegSetValueExW(
            reg,
            L"KdfSalt",
            0,
            REG_BINARY,
            newSalt.data(),
            SALT_BYTES) != ERROR_SUCCESS)
        {
            break;
        }

        if (RegSetValueExW(
            reg,
            L"KdfIterations",
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(
                &KDF_ITERATIONS),
            sizeof(KDF_ITERATIONS)) != ERROR_SUCCESS)
        {
            break;
        }

        if (RegSetValueExW(
            reg,
            L"KdfVersion",
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&version),
            sizeof(version)) != ERROR_SUCCESS)
        {
            break;
        }

        // 10. 새로운 MasterCheck 생성 및 저장.
        std::vector<BYTE> masterCheck;

        if (!EncryptText(
            newKey,
            L"MasterCheck",
            L"PM-VAULT-V1",
            masterCheck) ||
            !WriteBinaryValue(
                reg,
                L"MasterCheck",
                masterCheck))
        {
            break;
        }

        // 모든 트랜잭션 내 작업 성공.
        ok = true;

    } while (false);

    // 11. 레지스트리 핸들 정리.
    if (encryptedReg)
        RegCloseKey(encryptedReg);

    if (reg)
        RegCloseKey(reg);

    // 12. 모든 변경 사항을 확정하거나 취소.
    if (transaction != INVALID_HANDLE_VALUE)
    {
        if (ok)
        {
            ok = CommitTransaction(transaction) != FALSE;
        }

        if (!ok)
        {
            RollbackTransaction(transaction);
        }

        CloseHandle(transaction);
    }

    // 13. 새로운 암호화 키 제거.
    WipeKey(newKey);

    // 14. 임시 복호화 비밀번호 제거.
    for (auto& entry : restored)
    {
        WipeText(entry.password);
    }

    restored.clear();

    return ok;
}
