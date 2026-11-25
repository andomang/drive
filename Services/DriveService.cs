using System.Security.Cryptography;
using Dapper;

namespace MetaSearch.Services;

/// <summary>
/// 개인 클라우드 드라이브 서비스.
/// 인증(PBKDF2 해싱), 파일·폴더 CRUD, 즐겨찾기, 휴지통, 검색, 복사 등.
/// 물리 저장소: /mnt/ssd/drive/{userId}/ (관리자·회원 모두 SSD — 회원용 HDD는 유전원 허브를 달 때까지 보류)
/// </summary>
public class DriveService
{
    private readonly DbService _db;

    // 관리자 파일은 SSD, 일반 회원 파일은 HDD에 저장
    // drive 폴더는 디스크 '안'에 만들어 둠 → 디스크가 빠지면 폴더도 안 보여서 StorageOnline()이 false가 됨
    private const string ADMIN_ROOT = "/mnt/ssd/drive";
    // shortcut: 1TB HDD를 버스 전원으로 꽂으면 회전 시작 때 전원이 모자라 연결이 끊겨서(2026-11-23 5번),
    //   유전원 USB 허브를 달 때까지 회원도 SSD에 둠. 허브를 단 뒤 회원 폴더를 /mnt/hdd/drive 로 옮기고 이 값을 되돌릴 것
    private const string MEMBER_ROOT = "/mnt/ssd/drive";

    // 경로 계산은 요청마다 여러 번 일어나므로 관리자 여부를 기억해 둠 (권한 검사는 캐시 없이 IsAdmin으로 따로 함)
    // shortcut: 관리자 지정/해제는 서버를 재시작해야 저장 위치에 반영됨 — 자주 바뀌게 되면 만료 시간을 둘 것
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, bool> _adminCache = new();

    // PBKDF2 해싱 설정 — OWASP 권장 수준
    private const int SALT_SIZE = 16;
    private const int HASH_SIZE = 32;
    private const int ITERATIONS = 100_000;

    public DriveService(DbService db) => _db = db;

    // ═══════════════════════════════════════════════════════════════
    // 입력 검증 — 보안 유틸리티
    // ═══════════════════════════════════════════════════════════════

    /// <summary>파일명 정리 — 경로 탐색 방지, 특수문자·제어문자 제거 (XSS/인젝션 차단)</summary>
    public static string SanitizeFileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "unnamed";

        // 경로 구분자 제거 (디렉토리 탈출 방지)
        name = name.Replace("/", "").Replace("\\", "");
        // 상대 경로 토큰 제거
        name = name.Replace("..", "");
        // 제어 문자 제거 (null byte 등)
        name = new string(name.Where(c => !char.IsControl(c)).ToArray());
        // OS 예약 문자 제거
        foreach (char c in Path.GetInvalidFileNameChars())
            name = name.Replace(c.ToString(), "");
        // 선행 마침표 제거 (Unix 숨김 파일 방지)
        name = name.Trim().TrimStart('.');
        if (string.IsNullOrWhiteSpace(name)) return "unnamed";
        // 길이 제한 (파일시스템 호환 — ext4 max 255)
        if (name.Length > 200) name = name[..200];
        return name;
    }

    /// <summary>ILIKE 패턴 이스케이프 — %, _, \ 와일드카드 문자 무력화</summary>
    public static string EscapeLikePattern(string input)
    {
        return input
            .Replace("\\", "\\\\")
            .Replace("%", "\\%")
            .Replace("_", "\\_");
    }

    /// <summary>만료된 드라이브 세션 정리 (주기적 호출용)</summary>
    public void CleanExpiredSessions()
    {
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM drive_sessions WHERE expires_at < NOW()");
    }

    // ═══════════════════════════════════════════════════════════════
    // 스키마 마이그레이션 — 앱 시작 시 호출
    // ═══════════════════════════════════════════════════════════════

    /// <summary>새 컬럼 추가 (즐겨찾기, 휴지통)</summary>
    public void EnsureSchema()
    {
        using var conn = _db.OpenConnection();
        // 즐겨찾기 컬럼
        conn.Execute("ALTER TABLE drive_files ADD COLUMN IF NOT EXISTS is_starred BOOLEAN DEFAULT FALSE");
        // 휴지통 관련 컬럼
        conn.Execute("ALTER TABLE drive_files ADD COLUMN IF NOT EXISTS is_trashed BOOLEAN DEFAULT FALSE");
        conn.Execute("ALTER TABLE drive_files ADD COLUMN IF NOT EXISTS trashed_at TIMESTAMP");
        // 통합 계정 연결: 회원 아이디당 드라이브 계정 하나 (GetOrCreateUserForMember의 ON CONFLICT에 필요)
        conn.Execute("CREATE UNIQUE INDEX IF NOT EXISTS drive_users_username_uq ON drive_users (username)");
        // 회원별 용량 한도(바이트). NULL이면 기본값(MEMBER_QUOTA) — 관리자 화면에서 회원마다 조절
        conn.Execute("ALTER TABLE drive_users ADD COLUMN IF NOT EXISTS quota_bytes BIGINT");
    }

    // ═══════════════════════════════════════════════════════════════
    // 인증 관련
    // ═══════════════════════════════════════════════════════════════

    /// <summary>비밀번호를 PBKDF2-SHA256으로 해싱</summary>
    public string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, ITERATIONS, HashAlgorithmName.SHA256, HASH_SIZE);
        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    /// <summary>비밀번호 검증 — 타이밍 공격 방지용 고정시간 비교</summary>
    public bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split(':');
        if (parts.Length != 2) return false;
        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] expectedHash = Convert.FromBase64String(parts[1]);
        byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, ITERATIONS, HashAlgorithmName.SHA256, HASH_SIZE);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    // (예전 드라이브 전용 아이디·비밀번호 로그인은 없앰 — domang 통합 계정 SSO만 사용: GetOrCreateUserForMember + IssueToken)

    /// <summary>토큰으로 사용자 인증 — 유효하면 userId 반환 (형식 검증 포함)</summary>
    public int? ValidateToken(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        // 토큰 형식 검증 (64자 hex, 대소문자 무관) — 잘못된 형식은 DB 조회 없이 거부
        if (token.Length != 64 || !System.Text.RegularExpressions.Regex.IsMatch(token, "^[0-9a-fA-F]{64}$"))
            return null;
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<int?>(
            "SELECT user_id FROM drive_sessions WHERE token = @token AND expires_at > NOW()",
            new { token });
    }

    /// <summary>로그아웃 — 세션 토큰 삭제</summary>
    public void Logout(string? token)
    {
        if (string.IsNullOrEmpty(token)) return;
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM drive_sessions WHERE token = @token", new { token });
    }

    /// <summary>사용자 이름 조회</summary>
    public string? GetUsername(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<string>(
            "SELECT username FROM drive_users WHERE id = @userId", new { userId });
    }

    // ═══════════════════════════════════════════════════════════════
    // 파일·폴더 CRUD
    // ═══════════════════════════════════════════════════════════════

    // Dapper용 SELECT — snake_case → PascalCase 매핑
    private const string FILE_COLS =
        "id AS Id, file_name AS FileName, file_size AS FileSize, is_folder AS IsFolder, " +
        "parent_id AS ParentId, is_starred AS IsStarred, is_trashed AS IsTrashed, " +
        "trashed_at AS TrashedAt, created_at AS CreatedAt, updated_at AS UpdatedAt";

    /// <summary>해당 폴더의 하위 항목 목록 조회 (휴지통 제외, 폴더 우선, 이름순)</summary>
    public IEnumerable<DriveItem> ListFiles(int userId, int? parentId)
    {
        using var conn = _db.OpenConnection();
        string sql = parentId == null
            ? $"SELECT {FILE_COLS} FROM drive_files WHERE user_id = @userId AND parent_id IS NULL AND is_trashed = FALSE ORDER BY is_folder DESC, file_name"
            : $"SELECT {FILE_COLS} FROM drive_files WHERE user_id = @userId AND parent_id = @parentId AND is_trashed = FALSE ORDER BY is_folder DESC, file_name";

        return conn.Query<DriveItem>(sql, new { userId, parentId });
    }

    /// <summary>폴더 생성 — 새 폴더 ID 반환</summary>
    public int CreateFolder(int userId, string name, int? parentId)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingle<int>(
            @"INSERT INTO drive_files (user_id, file_name, is_folder, parent_id)
              VALUES (@userId, @name, TRUE, @parentId) RETURNING id",
            new { userId, name, parentId });
    }

    /// <summary>파일 메타데이터 DB에 등록 — 새 파일 ID 반환</summary>
    public int RegisterFile(int userId, string fileName, long fileSize, int? parentId)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingle<int>(
            @"INSERT INTO drive_files (user_id, file_name, file_size, is_folder, parent_id)
              VALUES (@userId, @fileName, @fileSize, FALSE, @parentId) RETURNING id",
            new { userId, fileName, fileSize, parentId });
    }

    /// <summary>같은 폴더에 동일 이름 파일이 있는지 확인 — 있으면 ID 반환</summary>
    public int? FindDuplicate(int userId, string fileName, int? parentId)
    {
        using var conn = _db.OpenConnection();
        string sql = parentId == null
            ? "SELECT id FROM drive_files WHERE user_id = @userId AND file_name = @fileName AND parent_id IS NULL AND is_trashed = FALSE AND is_folder = FALSE"
            : "SELECT id FROM drive_files WHERE user_id = @userId AND file_name = @fileName AND parent_id = @parentId AND is_trashed = FALSE AND is_folder = FALSE";
        return conn.QueryFirstOrDefault<int?>(sql, new { userId, fileName, parentId });
    }

    /// <summary>기존 파일 크기/날짜 업데이트 (덮어쓰기용)</summary>
    public void UpdateFileSize(int userId, int fileId, long newSize)
    {
        using var conn = _db.OpenConnection();
        conn.Execute(
            "UPDATE drive_files SET file_size = @newSize, updated_at = NOW() WHERE id = @fileId AND user_id = @userId",
            new { newSize, fileId, userId });
    }

    /// <summary>중복 방지 이름 생성 — "파일 (1).txt", "파일 (2).txt" 등</summary>
    public string GetUniqueName(int userId, string fileName, int? parentId)
    {
        string ext = Path.GetExtension(fileName);
        string nameOnly = Path.GetFileNameWithoutExtension(fileName);
        string candidate = fileName;
        int n = 1;
        while (FindDuplicate(userId, candidate, parentId) != null)
        {
            candidate = $"{nameOnly} ({n}){ext}";
            n++;
        }
        return candidate;
    }

    /// <summary>이 계정의 저장소 루트 (관리자 SSD / 회원 HDD)</summary>
    private string RootFor(int userId) => _adminCache.GetOrAdd(userId, IsAdmin) ? ADMIN_ROOT : MEMBER_ROOT;

    /// <summary>저장 디스크가 연결돼 있는지 — HDD가 빠진 채 쓰면 SSD의 빈 마운트 폴더에 몰래 저장되므로 쓰기 전에 반드시 확인</summary>
    public bool StorageOnline(int userId) => Directory.Exists(RootFor(userId));

    /// <summary>디스크 전체·남은 용량 표시용 마운트 경로 (/mnt/ssd 또는 /mnt/hdd)</summary>
    public string StorageMount(int userId) => Path.GetDirectoryName(RootFor(userId))!;

    /// <summary>파일 물리 저장 경로 반환</summary>
    public string GetPhysicalPath(int userId, int fileId)
    {
        return Path.Combine(RootFor(userId), userId.ToString(), fileId.ToString());
    }

    /// <summary>사용자 저장소 루트 디렉토리 경로</summary>
    public string EnsureUserDir(int userId)
    {
        return Path.Combine(RootFor(userId), userId.ToString());
    }

    /// <summary>상위 폴더로 쓸 수 있는지 — 본인 것 + 폴더 + 휴지통 아님 (null = 최상위라 항상 가능)
    /// 남의 폴더 번호나 파일 번호를 상위로 넣는 것을 막음</summary>
    public bool IsOwnFolder(int userId, int? folderId)
    {
        if (folderId == null) return true;
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<bool>(
            "SELECT EXISTS(SELECT 1 FROM drive_files WHERE id = @folderId AND user_id = @userId AND is_folder = TRUE AND is_trashed = FALSE)",
            new { folderId, userId });
    }

    /// <summary>파일 정보 조회</summary>
    public DriveItem? GetFile(int userId, int fileId)
    {
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<DriveItem>(
            $"SELECT {FILE_COLS} FROM drive_files WHERE id = @fileId AND user_id = @userId",
            new { fileId, userId });
    }

    /// <summary>파일/폴더 영구 삭제 (하위 항목 포함)</summary>
    public bool Delete(int userId, int fileId)
    {
        var item = GetFile(userId, fileId);
        if (item == null) return false;

        // 하위 항목 DB 기록은 parent_id 외래키(ON DELETE CASCADE)로 함께 지워짐. 물리 파일은 API에서 먼저 지움
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM drive_files WHERE id = @fileId AND user_id = @userId",
            new { fileId, userId });
        return true;
    }

    /// <summary>폴더 내 모든 파일 ID 재귀 조회 (물리 파일 삭제용)</summary>
    public IEnumerable<int> GetAllFileIdsInFolder(int userId, int folderId)
    {
        using var conn = _db.OpenConnection();
        // UNION(중복 제거)이라 혹시 폴더 고리가 있어도 무한 반복하지 않음, 본인 항목만 따라감
        return conn.Query<int>(
            @"WITH RECURSIVE sub AS (
                SELECT id, is_folder FROM drive_files WHERE parent_id = @folderId AND user_id = @userId
                UNION
                SELECT f.id, f.is_folder FROM drive_files f JOIN sub s ON f.parent_id = s.id WHERE f.user_id = @userId
              )
              SELECT id FROM sub WHERE is_folder = FALSE",
            new { folderId, userId });
    }

    /// <summary>파일/폴더 이름 변경</summary>
    public bool Rename(int userId, int fileId, string newName)
    {
        using var conn = _db.OpenConnection();
        int affected = conn.Execute(
            "UPDATE drive_files SET file_name = @newName, updated_at = NOW() WHERE id = @fileId AND user_id = @userId",
            new { newName, fileId, userId });
        return affected > 0;
    }

    /// <summary>파일/폴더를 다른 폴더로 이동</summary>
    public bool Move(int userId, int fileId, int? newParentId)
    {
        if (newParentId == fileId) return false;
        if (!IsOwnFolder(userId, newParentId)) return false;
        using var conn = _db.OpenConnection();
        // 폴더를 자기 하위 폴더 안으로 옮기면 고리가 생겨 경로 표시·삭제가 끝나지 않음 → 새 상위 폴더의 조상 중에 자신이 있으면 거부
        if (newParentId != null && conn.QueryFirstOrDefault<bool>(
            @"WITH RECURSIVE anc AS (
                SELECT id, parent_id FROM drive_files WHERE id = @newParentId AND user_id = @userId
                UNION
                SELECT f.id, f.parent_id FROM drive_files f JOIN anc a ON f.id = a.parent_id WHERE f.user_id = @userId
              )
              SELECT EXISTS(SELECT 1 FROM anc WHERE id = @fileId)",
            new { newParentId, fileId, userId }))
            return false;
        int affected = conn.Execute(
            "UPDATE drive_files SET parent_id = @newParentId, updated_at = NOW() WHERE id = @fileId AND user_id = @userId",
            new { newParentId, fileId, userId });
        return affected > 0;
    }

    /// <summary>현재 폴더 경로(브레드크럼) — 루트부터 현재까지</summary>
    public List<(int Id, string Name)> GetBreadcrumb(int userId, int? folderId)
    {
        if (folderId == null) return new();
        var crumbs = new List<(int, string)>();
        using var conn = _db.OpenConnection();
        int? current = folderId;

        // 깊이 제한: 데이터가 어떻게 꼬여 있어도 무한 반복하지 않게
        while (current != null && crumbs.Count < 64)
        {
            var folder = conn.QueryFirstOrDefault<(int Id, string Name, int? ParentId)>(
                "SELECT id, file_name AS Name, parent_id AS ParentId FROM drive_files WHERE id = @id AND user_id = @userId",
                new { id = current, userId });
            if (folder.Id == 0) break;
            crumbs.Insert(0, (folder.Id, folder.Name));
            current = folder.ParentId;
        }
        return crumbs;
    }

    /// <summary>사용자 전체 사용량(바이트) 조회</summary>
    public long GetUsage(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<long>(
            "SELECT COALESCE(SUM(file_size), 0) FROM drive_files WHERE user_id = @userId AND is_folder = FALSE AND is_trashed = FALSE",
            new { userId });
    }

    // ═══════════════════════════════════════════════════════════════
    // 즐겨찾기
    // ═══════════════════════════════════════════════════════════════

    /// <summary>즐겨찾기 토글 — 변경 후 상태 반환</summary>
    public bool ToggleStar(int userId, int fileId)
    {
        using var conn = _db.OpenConnection();
        return conn.QuerySingle<bool>(
            @"UPDATE drive_files SET is_starred = NOT is_starred, updated_at = NOW()
              WHERE id = @fileId AND user_id = @userId
              RETURNING is_starred",
            new { fileId, userId });
    }

    /// <summary>즐겨찾기 목록 조회</summary>
    public IEnumerable<DriveItem> ListStarred(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<DriveItem>(
            $"SELECT {FILE_COLS} FROM drive_files WHERE user_id = @userId AND is_starred = TRUE AND is_trashed = FALSE ORDER BY is_folder DESC, file_name",
            new { userId });
    }

    // ═══════════════════════════════════════════════════════════════
    // 휴지통
    // ═══════════════════════════════════════════════════════════════

    /// <summary>파일/폴더를 휴지통으로 이동</summary>
    public bool Trash(int userId, int fileId)
    {
        using var conn = _db.OpenConnection();
        int affected = conn.Execute(
            "UPDATE drive_files SET is_trashed = TRUE, trashed_at = NOW() WHERE id = @fileId AND user_id = @userId",
            new { fileId, userId });
        return affected > 0;
    }

    /// <summary>휴지통에서 복원</summary>
    public bool Restore(int userId, int fileId)
    {
        using var conn = _db.OpenConnection();
        int affected = conn.Execute(
            "UPDATE drive_files SET is_trashed = FALSE, trashed_at = NULL WHERE id = @fileId AND user_id = @userId",
            new { fileId, userId });
        return affected > 0;
    }

    /// <summary>휴지통 목록 조회</summary>
    public IEnumerable<DriveItem> ListTrash(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<DriveItem>(
            $"SELECT {FILE_COLS} FROM drive_files WHERE user_id = @userId AND is_trashed = TRUE ORDER BY trashed_at DESC",
            new { userId });
    }

    /// <summary>휴지통에서 영구 삭제할 모든 파일 ID 조회 — 휴지통에 넣은 폴더 '안'의 파일까지 포함
    /// (예전엔 휴지통 항목 자신만 골라서, 폴더째 버리면 DB 기록만 지워지고 실제 파일은 디스크에 남음
    ///  → 용량 한도가 비워진 것처럼 보여 반복하면 한도를 무시하고 디스크를 채울 수 있었음)</summary>
    public IEnumerable<int> GetTrashFileIds(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<int>(
            @"WITH RECURSIVE t AS (
                SELECT id, is_folder FROM drive_files WHERE user_id = @userId AND is_trashed = TRUE
                UNION
                SELECT f.id, f.is_folder FROM drive_files f JOIN t ON f.parent_id = t.id WHERE f.user_id = @userId
              )
              SELECT id FROM t WHERE is_folder = FALSE",
            new { userId });
    }

    /// <summary>휴지통 비우기 — 모든 휴지통 항목 영구 삭제</summary>
    public void EmptyTrash(int userId)
    {
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM drive_files WHERE user_id = @userId AND is_trashed = TRUE",
            new { userId });
    }

    // ═══════════════════════════════════════════════════════════════
    // 검색
    // ═══════════════════════════════════════════════════════════════

    /// <summary>파일명으로 검색 (대소문자 무시, 휴지통 제외, 와일드카드 이스케이프)</summary>
    public IEnumerable<DriveItem> Search(int userId, string query)
    {
        using var conn = _db.OpenConnection();
        // ILIKE 특수문자(%, _, \)를 이스케이프하여 리터럴 검색
        string escaped = EscapeLikePattern(query);
        return conn.Query<DriveItem>(
            $"SELECT {FILE_COLS} FROM drive_files WHERE user_id = @userId AND is_trashed = FALSE AND file_name ILIKE @pattern ESCAPE '\\' ORDER BY is_folder DESC, file_name LIMIT 100",
            new { userId, pattern = $"%{escaped}%" });
    }

    // ═══════════════════════════════════════════════════════════════
    // 최근 파일
    // ═══════════════════════════════════════════════════════════════

    /// <summary>최근 수정된 파일 목록 (폴더 제외)</summary>
    public IEnumerable<DriveItem> ListRecent(int userId, int limit = 30)
    {
        using var conn = _db.OpenConnection();
        return conn.Query<DriveItem>(
            $"SELECT {FILE_COLS} FROM drive_files WHERE user_id = @userId AND is_trashed = FALSE AND is_folder = FALSE ORDER BY updated_at DESC LIMIT @limit",
            new { userId, limit });
    }

    // ═══════════════════════════════════════════════════════════════
    // 파일 복사
    // ═══════════════════════════════════════════════════════════════

    /// <summary>파일 복제 — DB 레코드 생성, 물리 파일은 API에서 복사. 새 ID 반환</summary>
    public int? CopyFile(int userId, int fileId)
    {
        var item = GetFile(userId, fileId);
        if (item == null || item.IsFolder) return null;

        using var conn = _db.OpenConnection();
        // "파일명 (복사)" 형태로 이름 생성
        string ext = Path.GetExtension(item.FileName);
        string nameOnly = Path.GetFileNameWithoutExtension(item.FileName);
        string newName = $"{nameOnly} (복사){ext}";

        return conn.QuerySingle<int>(
            @"INSERT INTO drive_files (user_id, file_name, file_size, is_folder, parent_id)
              VALUES (@userId, @newName, @fileSize, FALSE, @parentId) RETURNING id",
            new { userId, newName, fileSize = item.FileSize, parentId = item.ParentId });
    }

    // ═══════════════════════════════════════════════════════════════
    // domang 통합 계정 연결 · 회원별 용량 · 관리자 열람
    // 드라이브 계정(drive_users.username)은 사이트 회원 아이디(members.userid)와 같은 값으로 연결
    // ═══════════════════════════════════════════════════════════════

    /// <summary>일반 회원 1명당 드라이브 용량 (5GB, HDD). 관리자는 무제한</summary>
    public const long MEMBER_QUOTA = 5L * 1024 * 1024 * 1024;

    /// <summary>사이트 회원의 드라이브 계정을 찾고, 없으면 만듦 (기존 가입자도 처음 들어올 때 자동 생성 → 5GB 지급)</summary>
    public int GetOrCreateUserForMember(string memberId)
    {
        using var conn = _db.OpenConnection();
        var id = conn.QueryFirstOrDefault<int?>(
            "SELECT id FROM drive_users WHERE username = @memberId", new { memberId });
        if (id != null) return id.Value;
        // 비밀번호 로그인은 쓰지 않으므로 검증이 항상 실패하는 값('!')을 넣음 (':' 구분자가 없어 VerifyPassword가 false)
        // ON CONFLICT: 같은 회원이 동시에 두 번 들어와도 계정이 하나만 생기게
        return conn.QuerySingle<int>(
            @"INSERT INTO drive_users (username, password_hash) VALUES (@memberId, '!')
              ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username RETURNING id",
            new { memberId });
    }

    /// <summary>세션 토큰 발급 (7일) — 통합 로그인(SSO)에서 사용</summary>
    public string IssueToken(int userId)
    {
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLower();
        using var conn = _db.OpenConnection();
        conn.Execute("DELETE FROM drive_sessions WHERE expires_at < NOW()");
        conn.Execute(
            "INSERT INTO drive_sessions (token, user_id, expires_at) VALUES (@token, @userId, NOW() + INTERVAL '7 days')",
            new { token, userId });
        return token;
    }

    /// <summary>토큰 검증 + 그 토큰이 지금 로그인한 사이트 회원의 것인지까지 확인 (한 번의 쿼리)
    /// → 같은 PC에서 다른 사람이 사이트에 로그인하면 이전 사람의 드라이브 토큰은 쓸 수 없음</summary>
    public int? ValidateTokenFor(string? token, string? memberId)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(memberId)) return null;
        if (token.Length != 64 || !System.Text.RegularExpressions.Regex.IsMatch(token, "^[0-9a-fA-F]{64}$")) return null;
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<int?>(
            @"SELECT s.user_id FROM drive_sessions s JOIN drive_users d ON d.id = s.user_id
              WHERE s.token = @token AND s.expires_at > NOW() AND d.username = @memberId",
            new { token, memberId });
    }

    /// <summary>이 드라이브 계정이 사이트 관리자(members.isadmin = 1)인지</summary>
    public bool IsAdmin(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<int?>(
            "SELECT m.isadmin FROM drive_users d JOIN members m ON TRIM(m.userid) = d.username WHERE d.id = @userId",
            new { userId }) == 1;
    }

    /// <summary>용량 한도 (바이트). 관리자는 null = 무제한</summary>
    public long? GetQuota(int userId)
    {
        if (IsAdmin(userId)) return null;
        using var conn = _db.OpenConnection();
        // 관리자가 따로 정한 값이 있으면 그 값, 없으면 기본 5GB
        return conn.QueryFirstOrDefault<long?>("SELECT quota_bytes FROM drive_users WHERE id = @userId", new { userId }) ?? MEMBER_QUOTA;
    }

    /// <summary>회원 한도 바꾸기 (null = 기본값으로) — 관리자 API에서만 호출. 바뀐 행이 없으면 false</summary>
    public bool SetQuota(int userId, long? quotaBytes)
    {
        using var conn = _db.OpenConnection();
        return conn.Execute("UPDATE drive_users SET quota_bytes = @quotaBytes WHERE id = @userId", new { userId, quotaBytes }) > 0;
    }

    /// <summary>용량 계산용 사용량 — 휴지통 파일도 디스크를 차지하므로 포함</summary>
    public long GetQuotaUsage(int userId)
    {
        using var conn = _db.OpenConnection();
        return conn.QueryFirstOrDefault<long>(
            "SELECT COALESCE(SUM(file_size), 0) FROM drive_files WHERE user_id = @userId AND is_folder = FALSE",
            new { userId });
    }

    /// <summary>addBytes만큼 더 저장하면 한도를 넘는지 (덮어쓰기는 freedBytes만큼 빠지는 것을 반영)</summary>
    // shortcut: 동시에 올린 파일 몇 개가 함께 검사를 통과하면 한도를 조금 넘을 수 있음 — 남용되면 회원별 잠금으로 바꿀 것
    public bool WouldExceedQuota(int userId, long addBytes, long freedBytes = 0)
    {
        long? quota = GetQuota(userId);
        return quota != null && GetQuotaUsage(userId) - freedBytes + addBytes > quota.Value;
    }

    /// <summary>관리자용: 드라이브 계정 전체와 사용량·파일 수 (사용량 많은 순)</summary>
    public IEnumerable<DriveUserRow> ListUsersWithUsage()
    {
        using var conn = _db.OpenConnection();
        return conn.Query<DriveUserRow>(
            @"SELECT d.id AS Id, d.username AS Username, COALESCE(TRIM(m.nickname), '') AS Nickname,
                     COALESCE(SUM(f.file_size) FILTER (WHERE f.is_folder = FALSE), 0) AS Usage,
                     COUNT(f.id) FILTER (WHERE f.is_folder = FALSE) AS Files,
                     COALESCE(m.isadmin, 0) = 1 AS IsAdmin,
                     d.quota_bytes AS QuotaBytes
              FROM drive_users d
              LEFT JOIN members m ON TRIM(m.userid) = d.username
              LEFT JOIN drive_files f ON f.user_id = d.id
              GROUP BY d.id, d.username, m.nickname, m.isadmin, d.quota_bytes
              ORDER BY Usage DESC, d.username").ToList();
    }
}

/// <summary>관리자 화면용 드라이브 계정 요약</summary>
public class DriveUserRow
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Nickname { get; set; } = "";
    public long Usage { get; set; }
    public long Files { get; set; }
    public bool IsAdmin { get; set; }
    /// <summary>따로 정한 한도(바이트). null이면 기본값</summary>
    public long? QuotaBytes { get; set; }
}

/// <summary>드라이브 파일/폴더 DTO</summary>
public class DriveItem
{
    public int Id { get; set; }
    public string FileName { get; set; } = "";
    public long FileSize { get; set; }
    public bool IsFolder { get; set; }
    public int? ParentId { get; set; }
    public bool IsStarred { get; set; }
    public bool IsTrashed { get; set; }
    public DateTime? TrashedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
