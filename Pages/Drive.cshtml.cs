using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MetaSearch.Pages;

/// <summary>
/// 클라우드 드라이브 진입 페이지.
/// 로그인/회원가입 폼 제공. 이미 인증된 사용자는 파일 탐색기로 리다이렉트.
/// </summary>
public class DriveModel : PageModel
{
    public void OnGet() { }
}
