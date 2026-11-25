using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MetaSearch.Pages;

/// <summary>
/// 클라우드 드라이브 파일 탐색기 페이지.
/// 인증은 JS에서 Bearer 토큰으로 처리 — 미인증 시 /drive로 리다이렉트.
/// </summary>
public class DriveFilesModel : PageModel
{
    public void OnGet() { }
}
