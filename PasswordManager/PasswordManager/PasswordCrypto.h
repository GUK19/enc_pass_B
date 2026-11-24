#pragma once

#include <string>
#include <vector>

// [데이터 모델] 암호 관리자에 표시/저장하는 비밀번호 항목 1개.
// id=고유한 번호, name=암호(비밀번호) 이름(NICK NAME, 예: "GitHub"), password=일반 비밀번호(암호) 원문.
// 마스터 암호를 설정해 놓은 경우에도 g_entries에 보관되는 password는 "복호화된 평문"이다.
struct PasswordEntry
{
    unsigned int id;
    std::wstring name;
    std::wstring password;
};

constexpr wchar_t REGISTRY_PATH[] =
L"Software\\enc_pass_B\\PasswordManager";
// 이 경로에는 다음과 같은 정보가 저장된다.
// 1. 마스터 암호 설정 여부: MasterPasswordEnabled (0 또는 1)
// 2. 암호화 키를 생성하는 데 필요한 정보(공개 가능해도 되는 정보): KdfSalt, KdfIterations, KdfVersion
// 3. 입력한 마스터 암호가 올바른지 확인하는 데이터: MasterCheck
//
// 마스터 암호를 설정하기 전에는 사용자가 추가한 비밀번호도 이 경로에 저장된다.
// 이때 비밀번호는 16진수 문자열로 변환되지만 암호화되지는 않는다.

// 두 CPP 파일에서 공통으로 사용하는 항목 번호 검사.
bool ParseEntryNumber(const std::wstring& text, unsigned int& number);

// 마스터 암호 설정 상태 및 메모리 정리.
bool LoadMasterPasswordEnabled(bool& enabled);
void WipeText(std::wstring& text);

// 마스터 암호 기반 암호화 저장소의 외부 인터페이스.
// 키는 이 인터페이스를 통해 GUI로 전달하지 않는다.
bool EnableEncryptionForExistingEntries(
    const std::wstring& password,
    const std::vector<PasswordEntry>& entries);

bool UnlockEncryptedStorage(
    const std::wstring& master,
    std::vector<PasswordEntry>& entries,
    unsigned int& nextId);

bool AddEncryptedPassword(
    const std::wstring& master,
    const PasswordEntry& entry);

bool DeleteEncryptedEntryFromRegistry(const PasswordEntry& entry);
bool DeleteLegacyPlaintextEntries(const std::vector<PasswordEntry>& entries);

// 마스터 암호 삭제 완료 및 암호화 관련 레지스트리 정리.
bool FinishMasterPasswordRemoval(bool& cleanupOk);
