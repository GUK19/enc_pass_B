// PasswordManager.cpp : 애플리케이션에 대한 진입점을 정의합니다.
//

#include "framework.h"
#include "PasswordManager.h"

#include <string>
#include <vector>

#define MAX_LOADSTRING 100

// 전역 변수:
HINSTANCE hInst;                                // 현재 인스턴스입니다.
WCHAR szTitle[MAX_LOADSTRING];                  // 제목 표시줄 텍스트입니다.
WCHAR szWindowClass[MAX_LOADSTRING];            // 기본 창 클래스 이름입니다.


struct PasswordEntry
{
    std::wstring name;
    std::wstring password;
};

std::vector<PasswordEntry> g_entries;

HWND g_nameEdit = nullptr;
HWND g_passwordEdit = nullptr;
HWND g_listBox = nullptr;

bool g_showPassword = false;

// Control IDs
constexpr int ID_PM_NAME = 2001;
constexpr int ID_PM_PASSWORD = 2002;
constexpr int ID_PM_LIST = 2003;
constexpr int ID_PM_ADD = 2004;
constexpr int ID_PM_LOAD = 2005;
constexpr int ID_PM_DELETE = 2006;
constexpr int ID_PM_SHOW = 2007;

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




// 이 코드 모듈에 포함된 함수의 선언을 전달합니다:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

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
       590, 470,
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

        g_listBox = CreateControl(
            hWnd, L"LISTBOX", L"",
            WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY,
            WS_EX_CLIENTEDGE,
            20, 145, 510, 220, ID_PM_LIST
        );

        CreateControl(
            hWnd,
            L"STATIC",
            L"Demo only - passwords are not encrypted or saved.",
            0, 0, 20, 380, 510, 20, 0
        );

        return 0;
    }
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // 메뉴 선택을 구문 분석합니다:
            switch (wmId)
            {// Add a password
            case ID_PM_ADD:
            {
                std::wstring name = ReadControlText(g_nameEdit);
                std::wstring password = ReadControlText(g_passwordEdit);

                if (name.empty() || password.empty())
                {
                    MessageBoxW(
                        hWnd,
                        L"Please enter a name and password.",
                        L"Warning",
                        MB_OK | MB_ICONWARNING
                    );
                    break;
                }

                LRESULT index = SendMessageW(
                    g_listBox,
                    LB_ADDSTRING,
                    0,
                    reinterpret_cast<LPARAM>(name.c_str())
                );

                if (index == LB_ERR || index == LB_ERRSPACE)
                {
                    MessageBoxW(
                        hWnd, L"Failed to add entry.",
                        L"Error", MB_OK | MB_ICONERROR
                    );
                    break;
                }

                g_entries.push_back({ name, password });

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

                g_entries.erase(g_entries.begin() + index);

                SendMessageW(
                    g_listBox, LB_DELETESTRING,
                    static_cast<WPARAM>(index), 0
                );

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
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: 여기에 hdc를 사용하는 그리기 코드를 추가합니다...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
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
