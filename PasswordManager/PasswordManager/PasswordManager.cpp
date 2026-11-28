// PasswordManager.cpp : 애플리케이션에 대한 진입점을 정의합니다.
//

#include "framework.h"
#include "PasswordManager.h"
#include "PasswordCrypto.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <algorithm>
#include <limits>
#define MAX_LOADSTRING 100


// 전역 변수:
HINSTANCE hInst;                                // 현재 인스턴스입니다.
WCHAR szTitle[MAX_LOADSTRING];                  // 제목 표시줄 텍스트입니다.
WCHAR szWindowClass[MAX_LOADSTRING];            // 기본 창 클래스 이름입니다.



std::vector<PasswordEntry> g_entries; // 실행 중 메모리에 보관하는 전체 항목 목록.

unsigned int g_nextId = 1; // 다음에 저장할 항목 ID (예: 마지막 ID가 3면 다음은 4).




constexpr UINT WM_PM_UNLOCK = WM_APP + 1;

enum class MasterMode {
    Setup,
    Unlock,
    EncryptAdd,
    DeleteMaster,
    ChangeMaster
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
constexpr int ID_PM_MASTER_DELETE = 2009;

constexpr int ID_MASTER_INPUT = 2101;
constexpr int ID_MASTER_CONFIRM = 2102;
constexpr int ID_MASTER_SHOW = 2103;
constexpr int ID_MASTER_OK = 2104;
constexpr int ID_MASTER_CANCEL = 2105;

constexpr int ID_MASTER_FORGOT = 2106;
constexpr int ID_MASTER_NEW = 2107;

constexpr int ID_RECOVERY_ONLINE = 2201;
constexpr int ID_RECOVERY_RESET = 2202;
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
// [마스터 암호 설정 안 했을 때 암호(비밀번호) 저장 함수] 암호(비밀번호)를 레지스트리의 REG_SZ로 저장한다.
// number = 항목 ID, name = 항목 표시명, password = 암호화되지 않은 암호(일반 비밀번호).
// 값 이름: "ID_항목명" (valueName)
// 값 데이터: ID + 이름HEX + 비밀번호HEX + "#" + CRC32 (data)
// 반환: true = 레지스트리 쓰기 성공, false = 열기/쓰기 실패.
// 주의: HEX 인코딩은 암호화가 아니므로 값을 읽으면 비밀번호를 복원할 수 있다.
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
////////////////////////////////////////////////////////////////////////////////////////////


// Load all password entries from the registry.
bool LoadEntriesFromRegistry(
    std::vector<PasswordEntry>& entries = g_entries,
    unsigned int& nextId = g_nextId)
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
        entries.clear();
        nextId = 1;
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

    entries = std::move(loaded);

    // Zero means the unsigned ID range was exhausted.
    nextId = largestId + 1;
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

///////////////////////////////////////////////////////////////////////////////////////////
// 마스터 암호를 검증하고 암호화된 비밀번호들을
// 기존 평문 저장 형식으로 되돌립니다.
bool RemoveMasterPassword(
    const std::wstring& master,
    bool& cleanupOk,
    bool& masterCheckRejected)
{
    cleanupOk = true;
    masterCheckRejected = false;

    std::vector<PasswordEntry> restored;
    unsigned int nextId = 1;

    // 1. 마스터 암호 검증 및 모든 비밀번호 복호화.
    if (!UnlockEncryptedStorage(
        master, restored, nextId, &masterCheckRejected))
        return false;

    bool ok = true;

    // 2. 복호화된 비밀번호들을 기존 평문 형식으로 저장.
    for (const auto& entry : restored)
    {
        if (!SaveEntryToRegistry(
            entry.id,
            entry.name,
            entry.password))
        {
            ok = false;
            break;
        }
    }

    // 3. 저장된 평문 데이터를 다시 읽어 정상 저장 여부 확인.
    std::vector<PasswordEntry> checked;
    unsigned int checkedNextId = 1;

    if (ok)
    {
        ok = LoadEntriesFromRegistry(checked, checkedNextId) &&
            checked.size() == restored.size() &&
            checkedNextId == nextId &&
            std::equal(
                restored.begin(),
                restored.end(),
                checked.begin(),
                [](const PasswordEntry& a,
                    const PasswordEntry& b)
                {
                    return a.id == b.id &&
                        a.name == b.name &&
                        a.password == b.password;
                }
            );
    }

    // 검증에 사용한 임시 비밀번호 제거.
    for (auto& entry : checked)
    {
        WipeText(entry.password);
    }

    checked.clear();

    // 4. 평문 저장이 확인되면 암호화 모드 해제.
    if (ok)
    {
        ok = FinishMasterPasswordRemoval(cleanupOk);
    }

    // 실패하면 복원 과정에서 저장한 평문을 제거합니다.
    // 기존 암호문과 KDF 정보는 유지됩니다.
    if (!ok)
    {
        cleanupOk = DeleteLegacyPlaintextEntries(restored);

        for (auto& entry : restored)
        {
            WipeText(entry.password);
        }

        return false;
    }

    // 5. 기존 메모리 목록을 복원된 목록으로 교체.
    for (auto& entry : g_entries)
    {
        WipeText(entry.password);
    }

    g_entries = std::move(restored);
    g_nextId = nextId;

    return true;
}
//////////////////////////////////////////////////////////////////////////////////////////
// 
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

void ShowMasterRecoveryWindow(HWND parent);
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
//  
//  함수: MyRegisterClass()
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
//   
//   함수: InitInstance(HINSTANCE, int)
//   용도: 인스턴스 핸들을 저장하고 주 창을 만듭니다.
//
//   이 함수를 통해 인스턴스 핸들을 전역 변수에 저장하고 주 프로그램 창을 만든 다음 표시합니다.
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
// [주 창 이벤트 처리] Windows가 전달하는 메시지별(UINT message)로 아래와 같이 동작을 나눈다.
// WM_CREATE = 화면 구성과 초기 로딩, WM_COMMAND = 버튼/메뉴 처리,
// WM_PM_UNLOCK = 마스터 암호 입력 요청, WM_DESTROY = 종료 정리.
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

        // ===== 마스터 암호 삭제 버튼 추가 시작 =====
        HWND masterDeleteButton = CreateControl(
            hWnd,
            L"BUTTON",
            L"마스터 암호 삭제",
            WS_TABSTOP | BS_PUSHBUTTON,
            0,
            205, 403, 175, 32,
            ID_PM_MASTER_DELETE
        );

        // 마스터 암호 설정 및 인증 전에는 표시하지 않습니다.
        ShowWindow(masterDeleteButton, SW_HIDE);
        EnableWindow(masterDeleteButton, FALSE);
        // ===== 마스터 암호 삭제 버튼 추가 끝 =====

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
                ShowMasterPasswordWindow(
                    hWnd,
                    MasterMode::ChangeMaster
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
        // ===== 마스터 암호 삭제 버튼 이벤트 시작 =====
        case ID_PM_MASTER_DELETE:
        {
            if (!g_storageReady || !g_masterEnabled)
                break;

            int answer = MessageBoxW(
                hWnd,
                L"마스터 암호를 삭제하면 저장된 모든 비밀번호가\n"
                L"암호화되지 않은 상태로 레지스트리에 저장됩니다.\n\n"
                L"계속하시겠습니까?",
                L"마스터 암호 삭제",
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2
            );

            if (answer == IDYES)
            {
                ShowMasterPasswordWindow(
                    hWnd,
                    MasterMode::DeleteMaster
                );
            }

            break;
        }
        // ===== 마스터 암호 삭제 버튼 이벤트 끝 =====
        // 
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
    int height = mode == MasterMode::ChangeMaster
        ? 410 : 350;

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
        : mode == MasterMode::DeleteMaster
        ? L"마스터 암호 삭제"
        : mode == MasterMode::ChangeMaster
        ? L"마스터 암호 변경"
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
        // ===== 마스터 암호 변경 창 구성 시작 =====
        if (g_masterMode == MasterMode::ChangeMaster)
        {
            CreateControl(
                hWnd, L"STATIC",
                L"기존 마스터 암호와 새로운 마스터 암호를 입력하세요.",
                0, 0, 20, 20, 410, 20, 0
            );

            CreateControl(
                hWnd, L"STATIC",
                L"새로운 마스터 암호는 8자 이상이어야 합니다.",
                0, 0, 20, 42, 410, 20, 0
            );

            CreateControl(
                hWnd, L"STATIC", L"",
                SS_ETCHEDHORZ,
                0,
                20, 70, 410, 2,
                0
            );

            // 1. 기존 마스터 암호 입력.
            CreateControl(
                hWnd, L"STATIC",
                L"기존 마스터 암호 입력",
                0, 0, 20, 88, 410, 20, 0
            );

            g_masterInput = CreateControl(
                hWnd, L"EDIT", L"",
                WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                WS_EX_CLIENTEDGE,
                20, 110, 410, 28,
                ID_MASTER_INPUT
            );

            // 2. 새로운 마스터 암호 입력.
            CreateControl(
                hWnd, L"STATIC",
                L"새로운 마스터 암호 입력",
                0, 0, 20, 145, 410, 20, 0
            );

            HWND newInput = CreateControl(
                hWnd, L"EDIT", L"",
                WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                WS_EX_CLIENTEDGE,
                20, 167, 410, 28,
                ID_MASTER_NEW
            );

            // 3. 새로운 마스터 암호 확인.
            CreateControl(
                hWnd, L"STATIC",
                L"새로운 마스터 암호 확인",
                0, 0, 20, 202, 410, 20, 0
            );

            g_masterConfirm = CreateControl(
                hWnd, L"EDIT", L"",
                WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                WS_EX_CLIENTEDGE,
                20, 224, 410, 28,
                ID_MASTER_CONFIRM
            );

            CreateControl(
                hWnd, L"BUTTON", L"암호 보이기",
                WS_TABSTOP | BS_AUTOCHECKBOX,
                0,
                20, 267, 150, 25,
                ID_MASTER_SHOW
            );

            g_masterOk = CreateControl(
                hWnd, L"BUTTON", L"확인",
                WS_TABSTOP | BS_DEFPUSHBUTTON,
                0,
                265, 315, 75, 30,
                ID_MASTER_OK
            );

            CreateControl(
                hWnd, L"BUTTON", L"취소",
                WS_TABSTOP | BS_PUSHBUTTON,
                0,
                350, 315, 80, 30,
                ID_MASTER_CANCEL
            );

            // 필수 입력란이나 확인 버튼의 생성 실패 확인.
            if (!g_masterInput ||
                !newInput ||
                !g_masterConfirm ||
                !g_masterOk)
            {
                return -1;
            }

            // 세 입력값이 유효하기 전에는 확인 버튼 비활성화.
            EnableWindow(g_masterOk, FALSE);

            return 0;
        }
        // ===== 마스터 암호 변경 창 구성 끝 =====
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
            : g_masterMode == MasterMode::DeleteMaster
            ? L"마스터 암호 삭제를 위해 기존 암호를 확인합니다."
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
        // 암호관리자 잠금 해제 창에서만 표시합니다.
        if (g_masterMode == MasterMode::Unlock)
        {
            CreateControl(
                hWnd,
                L"BUTTON",
                L"마스터 암호를 잊어버렸습니다",
                WS_TABSTOP | BS_PUSHBUTTON,
                0,
                20, 265, 235, 30,
                ID_MASTER_FORGOT
            );
        }
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
        case ID_MASTER_NEW:
        {
            if (notification == EN_CHANGE)
            {
                // 마스터 암호 변경 창의 초기 생성 중에는
                // 모든 입력란이 생성될 때까지 검증하지 않습니다.
                if (g_masterMode == MasterMode::ChangeMaster &&
                    !g_masterOk)
                {
                    return 0;
                }

                std::wstring password =
                    ReadControlText(g_masterInput);

                std::wstring confirm =
                    ReadControlText(g_masterConfirm);

                bool valid =
                    g_masterMode == MasterMode::Setup
                    ? password.length() >= 8 &&
                    password == confirm
                    : !password.empty();

                // 마스터 암호 변경 모드의 추가 검증.
                if (g_masterMode == MasterMode::ChangeMaster)
                {
                    std::wstring newPassword =
                        ReadControlText(
                            GetDlgItem(hWnd, ID_MASTER_NEW)
                        );

                    valid =
                        !password.empty() &&
                        newPassword.length() >= 8 &&
                        newPassword == confirm;

                    WipeText(newPassword);
                }

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
                // 마스터 암호 변경 창의 새로운 입력란에도 적용.
                if (g_masterMode == MasterMode::ChangeMaster)
                {
                    HWND newInput =
                        GetDlgItem(hWnd, ID_MASTER_NEW);

                    SendMessageW(
                        newInput,
                        EM_SETPASSWORDCHAR,
                        show ? 0 : L'*',
                        0
                    );

                    InvalidateRect(
                        newInput, nullptr, TRUE
                    );
                }
            }

            return 0;
        }

        // Confirm password
        case ID_MASTER_OK:
        {
            // ===== 마스터 암호 변경 처리 시작 =====
            if (g_masterMode == MasterMode::ChangeMaster)
            {
                HWND newInput =
                    GetDlgItem(hWnd, ID_MASTER_NEW);

                std::wstring oldMaster =
                    ReadControlText(g_masterInput);

                std::wstring newMaster =
                    ReadControlText(newInput);

                std::wstring newConfirm =
                    ReadControlText(g_masterConfirm);

                // 1. 입력값 재검증.
                bool valid =
                    !oldMaster.empty() &&
                    newMaster.length() >= 8 &&
                    newMaster == newConfirm;


                if (!valid)
                {
                    WipeText(oldMaster);
                    WipeText(newMaster);
                    WipeText(newConfirm);

                    SetWindowTextW(g_masterInput, L"");
                    SetWindowTextW(newInput, L"");
                    SetWindowTextW(g_masterConfirm, L"");

                    MessageBoxW(
                        hWnd,
                        L"기존 마스터 암호를 입력하고\n"
                        L"8자 이상의 새로운 마스터 암호를 동일하게 입력하세요.",
                        L"경고",
                        MB_OK | MB_ICONWARNING
                    );

                    SetFocus(g_masterInput);

                    return 0;
                }

                // 2. 기존 마스터 암호 검증 및 변경 작업.
                bool changed =
                    g_masterEnabled &&
                    g_storageReady &&
                    ChangeMasterPassword(
                        oldMaster,
                        newMaster
                    );

                // 3. 임시 마스터 암호 제거.
                WipeText(oldMaster);
                WipeText(newMaster);
                WipeText(newConfirm);

                SetWindowTextW(g_masterInput, L"");
                SetWindowTextW(newInput, L"");
                SetWindowTextW(g_masterConfirm, L"");

                // 4. 변경 실패.
                if (!changed)
                {
                    MessageBoxW(
                        hWnd,
                        L"기존 마스터 암호 확인 또는 변경 작업에 실패했습니다.\n"
                        L"입력한 암호를 확인하고 다시 시도해 주세요.",
                        L"Error",
                        MB_OK | MB_ICONERROR
                    );

                    SetFocus(g_masterInput);

                    return 0;
                }

                // 5. 변경 성공.
                MessageBoxW(
                    hWnd,
                    L"마스터 암호가 변경되었습니다.",
                    L"안내",
                    MB_OK | MB_ICONINFORMATION
                );

                DestroyWindow(hWnd);

                return 0;
            }
            // ===== 마스터 암호 변경 처리 끝 =====
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
            bool cleanupOk = true;
            bool masterCheckRejected = false;

            // 1. Master password setup.
            if (g_masterMode == MasterMode::Setup)
            {
                success =
                    EnableEncryptionForExistingEntries(password, g_entries);

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

                    // 마스터 암호 삭제 버튼 표시 및 활성화.
                    ShowWindow(
                        GetDlgItem(owner, ID_PM_MASTER_DELETE),
                        SW_SHOW
                    );

                    EnableWindow(
                        GetDlgItem(owner, ID_PM_MASTER_DELETE),
                        TRUE
                    );
                }
            }

            
            // 2. Unlock encrypted storage.
            else if (g_masterMode == MasterMode::Unlock)
            {
                success = UnlockEncryptedStorage(
                    password,
                    g_entries,
                    g_nextId,
                    &masterCheckRejected
                );

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
                    ///////////////////////////////////////////////////////////////////
                    // 마스터 암호 인증에 성공한 경우 삭제 버튼 표시.
                    ShowWindow(
                        GetDlgItem(owner, ID_PM_MASTER_DELETE),
                        SW_SHOW
                    );

                    EnableWindow(
                        GetDlgItem(owner, ID_PM_MASTER_DELETE),
                        TRUE
                    );
                    /////////////////////////////////////////////////////////////////////
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
                        AddEncryptedPassword(
                            password,
                            entry,
                            &masterCheckRejected
                        );

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
            // 4. Delete the master password.
            else if (g_masterMode == MasterMode::DeleteMaster)
            {
                success = RemoveMasterPassword(
                    password,
                    cleanupOk,
                    masterCheckRejected
                );

                if (success)
                {
                    // 암호화 모드 해제.
                    g_masterEnabled = false;
                    g_storageReady = true;

                    // 기존 버튼 이름으로 복귀.
                    SetWindowTextW(
                        GetDlgItem(owner, ID_PM_MASTER),
                        L"마스터 암호 설정"
                    );

                    // 마스터 암호 삭제 버튼 숨기기 및 비활성화.
                    ShowWindow(
                        GetDlgItem(owner, ID_PM_MASTER_DELETE),
                        SW_HIDE
                    );

                    EnableWindow(
                        GetDlgItem(owner, ID_PM_MASTER_DELETE),
                        FALSE
                    );

                    // 상태 표시 문구 변경.
                    SetWindowTextW(
                        g_statusLabel,
                        L"Demo - Registry HEX storage. Not encrypted."
                    );

                    RefreshListBox();

                    SetWindowTextW(g_nameEdit, L"");
                    SetWindowTextW(g_passwordEdit, L"");
                }
                }
            // Clear temporary master password buffers.
            WipeText(password);
            WipeText(confirm);

            SetWindowTextW(g_masterInput, L"");
            SetWindowTextW(g_masterConfirm, L"");
            // 마스터 암호 삭제 과정에서 레지스트리 정리에 실패한 경우.
            if (g_masterMode == MasterMode::DeleteMaster && !cleanupOk)
            {
                MessageBoxW(
                    hWnd,
                    success
                    ? L"평문 모드로 전환했지만 기존 암호화 데이터의\n"
                    L"정리를 완료하지 못했습니다."
                    : L"마스터 암호 삭제에 실패했으며 복원 과정에서\n"
                    L"저장한 일부 평문을 제거하지 못했을 수 있습니다.",
                    L"Warning",
                    MB_OK | MB_ICONWARNING
                );
            }   
            if (!success)
            {
                // 1. 암호 관리자 잠금 해제 중 마스터 암호 인증 실패.
                if (masterCheckRejected &&
                    g_masterMode == MasterMode::Unlock)
                {
                    MessageBoxW(
                        hWnd,
                        L"마스터 암호가 틀렸습니다.\n"
                        L"마스터 암호를 확인해 주세요.",
                        L"경고",
                        MB_OK | MB_ICONWARNING
                    );
                }

                // 2. 비밀번호 저장 또는 마스터 암호 삭제 중 인증 실패.
                else if (masterCheckRejected &&
                    (g_masterMode == MasterMode::EncryptAdd ||
                        g_masterMode == MasterMode::DeleteMaster))
                {
                    MessageBoxW(
                        hWnd,
                        L"기존 마스터 암호를 제대로 입력해 주세요.",
                        L"경고",
                        MB_OK | MB_ICONWARNING
                    );
                }

                // 3. 마스터 암호 인증 실패 이외의 기존 오류 처리.
                else
                {
                    MessageBoxW(
                        hWnd,
                        L"암호 확인 또는 레지스트리 처리에 실패했습니다.\n"
                        L"기존 데이터를 보호하기 위해 작업을 중단합니다.",
                        L"Error",
                        MB_OK | MB_ICONERROR
                    );
                }

                return 0;
            }

            MasterMode completedMode = g_masterMode;

            DestroyWindow(hWnd);

            // Remove old plaintext registry entries.
            if (completedMode == MasterMode::Setup ||
                completedMode == MasterMode::Unlock)
            {
                if (!DeleteLegacyPlaintextEntries(g_entries))
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
        // 마스터 암호 분실 안내 창 열기.
        case ID_MASTER_FORGOT:
        {
            if (notification == BN_CLICKED &&
                g_masterMode == MasterMode::Unlock &&
                g_masterEnabled &&
                !g_storageReady)
            {
                ShowMasterRecoveryWindow(hWnd);
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
        // 마스터 암호 변경 창을 닫을 때 입력란 정리.
        if (g_masterMode == MasterMode::ChangeMaster)
        {
            SetWindowTextW(g_masterInput, L"");

            SetWindowTextW(
                GetDlgItem(hWnd, ID_MASTER_NEW),
                L""
            );

            SetWindowTextW(g_masterConfirm, L"");
        }
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
// 마스터 암호 복구 안내 창의 메시지 처리기.
LRESULT CALLBACK RecoveryWndProc(
    HWND hWnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        // 왼쪽 안내 문구.
        CreateControl(
            hWnd,
            L"STATIC",
            L"마스터 암호를 등록하셨나요?",
            SS_CENTER,
            0,
            20, 35, 270, 25,
            0
        );

        // 왼쪽 버튼.
        CreateControl(
            hWnd,
            L"BUTTON",
            L"온라인에서 확인해 보세요",
            WS_TABSTOP | BS_PUSHBUTTON,
            0,
            55, 90, 200, 36,
            ID_RECOVERY_ONLINE
        );

        // 가운데 세로 구분선.
        CreateControl(
            hWnd,
            L"STATIC",
            L"",
            SS_ETCHEDVERT,
            0,
            300, 20, 2, 140,
            0
        );

        // 오른쪽 안내 문구.
        CreateControl(
            hWnd,
            L"STATIC",
            L"암호관리자를 새로 시작하시겠어요?",
            SS_CENTER,
            0,
            310, 35, 270, 25,
            0
        );

        // 오른쪽 버튼.
        CreateControl(
            hWnd,
            L"BUTTON",
            L"암호관리자 초기화하기",
            WS_TABSTOP | BS_PUSHBUTTON,
            0,
            345, 90, 200, 36,
            ID_RECOVERY_RESET
        );

        return 0;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        int notification = HIWORD(wParam);

        if (notification != BN_CLICKED)
            return 0;

        switch (id)
        {
            // 1. 온라인 마스터 암호 확인.
        case ID_RECOVERY_ONLINE:
        {
            MessageBoxW(
                hWnd,
                L"추후 업데이트 예정",
                L"안내",
                MB_OK | MB_ICONINFORMATION
            );

            return 0;
        }

        // 2. 암호관리자 초기화.
        case ID_RECOVERY_RESET:
        {
            HWND unlockWindow =
                GetWindow(hWnd, GW_OWNER);

            if (!unlockWindow)
                return 0;

            HWND mainWindow =
                GetWindow(unlockWindow, GW_OWNER);

            if (!mainWindow ||
                g_masterMode != MasterMode::Unlock ||
                !g_masterEnabled ||
                g_storageReady)
            {
                return 0;
            }

            // 초기화 진행 전 사용자 동의 확인.
            int answer = MessageBoxW(
                hWnd,
                L"초기화를 하면 기존에 암호관리자에 저장된 "
                L"모든 암호 정보 또한 삭제됩니다.\n\n"
                L"삭제된 정보는 복구할 수 없습니다.\n\n"
                L"암호관리자를 초기화하시겠습니까?",
                L"암호관리자 초기화",
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2
            );

            if (answer != IDYES)
                return 0;

            // 레지스트리 초기화.
            if (!ResetPasswordManagerStorage())
            {
                MessageBoxW(
                    hWnd,
                    L"암호관리자 초기화를 완료하지 못했습니다.\n"
                    L"일부 데이터가 이미 삭제되었을 수 있습니다.\n"
                    L"초기화를 다시 시도해 주세요.",
                    L"Error",
                    MB_OK | MB_ICONERROR
                );

                return 0;
            }

            // 메모리에 있는 비밀번호 초기화.
            for (auto& entry : g_entries)
            {
                WipeText(entry.password);
            }

            g_entries.clear();
            g_nextId = 1;

            // 암호관리자 상태 초기화.
            g_masterEnabled = false;
            g_storageReady = true;

            // 마스터 암호 설정 버튼 이름 복원.
            SetWindowTextW(
                GetDlgItem(mainWindow, ID_PM_MASTER),
                L"마스터 암호 설정"
            );

            EnableWindow(
                GetDlgItem(mainWindow, ID_PM_MASTER),
                TRUE
            );

            // 마스터 암호 삭제 버튼 숨기기.
            ShowWindow(
                GetDlgItem(mainWindow, ID_PM_MASTER_DELETE),
                SW_HIDE
            );

            EnableWindow(
                GetDlgItem(mainWindow, ID_PM_MASTER_DELETE),
                FALSE
            );

            // 암호화 상태 표시 문구 복원.
            SetWindowTextW(
                g_statusLabel,
                L"Demo - Registry HEX storage. Not encrypted."
            );

            // 비밀번호 목록 및 입력란 초기화.
            RefreshListBox();

            SetWindowTextW(g_nameEdit, L"");
            SetWindowTextW(g_passwordEdit, L"");

            // 기본 기능 다시 활성화.
            EnableWindow(
                GetDlgItem(mainWindow, ID_PM_ADD),
                TRUE
            );

            EnableWindow(
                GetDlgItem(mainWindow, ID_PM_LOAD),
                TRUE
            );

            EnableWindow(
                GetDlgItem(mainWindow, ID_PM_DELETE),
                TRUE
            );

            // 기존 마스터 암호 입력란 초기화.
            SetWindowTextW(g_masterInput, L"");
            SetWindowTextW(g_masterConfirm, L"");

            MessageBoxW(
                hWnd,
                L"암호관리자 초기화가 완료되었습니다.",
                L"안내",
                MB_OK | MB_ICONINFORMATION
            );

            // 복구 안내 창부터 닫습니다.
            DestroyWindow(hWnd);

            // 기존 잠금 해제 창도 닫습니다.
            DestroyWindow(unlockWindow);

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

        // 기존 잠금 해제 창을 다시 활성화합니다.
        if (owner)
        {
            EnableWindow(owner, TRUE);
            SetForegroundWindow(owner);
            SetActiveWindow(owner);
        }

        return 0;
    }
    }

    return DefWindowProcW(
        hWnd, message, wParam, lParam
    );
}
// 마스터 암호 복구 안내 창 생성 및 표시.
void ShowMasterRecoveryWindow(HWND parent)
{
    const wchar_t CLASS_NAME[] =
        L"MasterRecoveryWindowClass";

    static bool registered = false;

    // 새로운 창 클래스 등록.
    if (!registered)
    {
        WNDCLASSW wc = {};

        wc.lpfnWndProc = RecoveryWndProc;
        wc.hInstance = hInst;
        wc.lpszClassName = CLASS_NAME;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);

        if (!RegisterClassW(&wc))
        {
            MessageBoxW(
                parent,
                L"복구 안내 창 클래스를 등록하지 못했습니다.",
                L"Error",
                MB_OK | MB_ICONERROR
            );

            return;
        }

        registered = true;
    }

    // 기존 잠금 해제 창의 위치 확인.
    RECT parentRect = {};

    if (!GetWindowRect(parent, &parentRect))
        return;

    int width = 620;
    int height = 240;

    // 기존 잠금 해제 창의 중앙에 배치.
    int x = parentRect.left +
        ((parentRect.right - parentRect.left) - width) / 2;

    int y = parentRect.top +
        ((parentRect.bottom - parentRect.top) - height) / 2;

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        L"마스터 암호 복구 안내",
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
            L"마스터 암호 복구 안내 창을 생성하지 못했습니다.",
            L"Error",
            MB_OK | MB_ICONERROR
        );

        return;
    }

    // 복구 안내 창을 닫기 전까지
    // 기존 잠금 해제 창을 비활성화합니다.
    EnableWindow(parent, FALSE);

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    SetForegroundWindow(window);
}
