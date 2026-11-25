// ============================================================
// DriveApi.cs - Cloud Drive API (/api/drive/*) 전부
//   예전엔 Program.cs 안에 메타서치·게임 API 와 섞여 있었음 → 드라이브 저장소(andomang/drive)에
//   드라이브 코드만 따로 올릴 수 있게 이 파일로 분리. 동작은 그대로 (Program.cs 에서 app.MapDriveApi() 한 줄로 등록)
//   함께 쓰는 파일: Services/DriveService.cs, Pages/Drive*.cshtml, wwwroot/js·css 의 드라이브 화면
// ============================================================
using MetaSearch.Services;

namespace MetaSearch;

public static class DriveApi
{
    public static void MapDriveApi(this WebApplication app)
    {
        // ═══════════════════════════════════════════════════════════════════════
        // 클라우드 드라이브 API (/api/drive/*)
        // ═══════════════════════════════════════════════════════════════════════

        // 드라이브 스키마 지연 초기화 플래그 — 첫 API 호출 시 컬럼 존재 보장
        var _schemaReady = false;
        void EnsureDriveSchema(DriveService drive)
        {
            if (_schemaReady) return;
            try { drive.EnsureSchema(); _schemaReady = true; }
            catch (Exception ex) { Console.Error.WriteLine("[Drive] 지연 스키마 초기화 실패: " + ex.Message); }
        }

        // 드라이브 인증 헬퍼 — Bearer 토큰에서 userId 추출 + 스키마 보장
        int? DriveAuth(HttpContext ctx, DriveService drive)
        {
            EnsureDriveSchema(drive);
            string? auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
            if (auth == null || !auth.StartsWith("Bearer ")) return null;
            // 토큰 주인이 지금 사이트에 로그인한 회원과 같아야 함 (공용 PC에서 남의 드라이브가 열리는 것 방지)
            return drive.ValidateTokenFor(auth[7..], ctx.Session.GetString("UserID"));
        }

        // 관리자 전용: 드라이브 토큰이 사이트 관리자(members.isadmin = 1) 것일 때만 통과
        int? DriveAdminAuth(HttpContext ctx, DriveService drive)
        {
            int? u = DriveAuth(ctx, drive);
            return u != null && drive.IsAdmin(u.Value) ? u : null;
        }

        // 용량 초과 응답 (화면에서 '용량 초과'로 표시)
        IResult QuotaExceeded() => Results.Json(new { error = "quota", message = "드라이브 용량(5GB)을 넘어 저장할 수 없습니다." }, statusCode: 413);
        // 저장 디스크(회원용 HDD)가 빠져 있을 때 — 쓰기를 거절해야 SSD의 빈 마운트 폴더에 몰래 저장되지 않음
        IResult StorageOffline() => Results.Json(new { error = "storage", message = "회원 저장소 점검 중입니다. 잠시 후 다시 시도해 주세요." }, statusCode: 503);

        // 드라이브 진단 엔드포인트 — 문제 발생 시 환경/DB 상태 확인용
        // 예전 관리자 주소 → 통합 관리자 페이지의 해당 메뉴로 (즐겨찾기·옛 링크 유지)
        app.MapGet("/drive/admin", () => Results.Redirect("/admin#drive"));

        // 서버 OS·런타임·DB 구조가 드러나므로 관리자만
        app.MapGet("/api/drive/diag", (HttpContext ctx, DriveService drive, DbService db) =>
        {
            int? userId = DriveAdminAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            var info = new Dictionary<string, object>();
            info["userId"] = userId.Value;
            info["time"] = DateTime.UtcNow.ToString("o");
            info["runtime"] = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
            info["os"] = System.Runtime.InteropServices.RuntimeInformation.OSDescription;

            // DB 연결 테스트
            try
            {
                using var conn = db.OpenConnection();
                // drive_files 테이블 존재 여부 + 컬럼 확인
                var cols = Dapper.SqlMapper.Query<string>(conn,
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'drive_files' ORDER BY ordinal_position");
                info["drive_files_columns"] = cols.ToList();
                // 파일 수
                var cnt = Dapper.SqlMapper.QueryFirstOrDefault<long>(conn,
                    "SELECT COUNT(*) FROM drive_files WHERE user_id = @userId", new { userId = userId.Value });
                info["fileCount"] = cnt;
                // 휴지통 아닌 파일 수
                try
                {
                    var activeCnt = Dapper.SqlMapper.QueryFirstOrDefault<long>(conn,
                        "SELECT COUNT(*) FROM drive_files WHERE user_id = @userId AND is_trashed = FALSE", new { userId = userId.Value });
                    info["activeFileCount"] = activeCnt;
                }
                catch (Exception ex) { info["activeFileCountError"] = ex.Message; }
                info["dbOk"] = true;
            }
            catch (Exception ex)
            {
                info["dbOk"] = false;
                info["dbError"] = ex.Message;
            }

            // 스토리지 경로 확인
            try
            {
                string userDir = drive.EnsureUserDir(userId.Value);
                info["storagePath"] = userDir;
                info["storageExists"] = Directory.Exists(userDir);
                if (Directory.Exists(userDir))
                    info["storageFileCount"] = Directory.GetFiles(userDir).Length;
            }
            catch (Exception ex) { info["storageError"] = ex.Message; }

            return Results.Json(info);
        });

        // 통합 로그인(SSO) — domang 사이트에 로그인한 세션이면 그 회원의 드라이브 토큰을 발급
        // 드라이브 계정이 없으면 이때 만들어짐 (기존 가입자도 처음 들어올 때 5GB 공간이 생김)
        app.MapPost("/api/drive/sso", (HttpContext ctx, DriveService drive) =>
        {
            EnsureDriveSchema(drive);
            ctx.Response.Headers.CacheControl = "no-store";
            string? uid = ctx.Session.GetString("UserID");
            if (uid == null) return Results.Json(new { error = "login_required" }, statusCode: 401);
            int driveUser = drive.GetOrCreateUserForMember(uid);
            return Results.Json(new { token = drive.IssueToken(driveUser) });
        });

        // 로그아웃
        app.MapPost("/api/drive/logout", (HttpContext ctx, DriveService drive) =>
        {
            string? auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
            if (auth != null && auth.StartsWith("Bearer ")) drive.Logout(auth[7..]);
            return Results.Ok();
        });

        // 내 정보
        app.MapGet("/api/drive/me", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();
            string? username = drive.GetUsername(userId.Value);
            return Results.Json(new { userId, username, isAdmin = drive.IsAdmin(userId.Value), quota = drive.GetQuota(userId.Value) });
        });

        // 사용량 조회
        app.MapGet("/api/drive/usage", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();
            long usage = drive.GetUsage(userId.Value);

            // 이 계정이 쓰는 디스크(관리자 SSD / 회원 HDD)의 전체/사용가능 용량
            long total = 0, free = 0;
            try
            {
                var di = new DriveInfo(drive.StorageMount(userId.Value));
                total = di.TotalSize;
                free = di.AvailableFreeSpace;
            }
            catch { }

            // quota: 회원은 5GB, 관리자는 null(무제한) / quotaUsed: 휴지통까지 포함한 사용량
            return Results.Json(new { usage, total, free, quota = drive.GetQuota(userId.Value), quotaUsed = drive.GetQuotaUsage(userId.Value) });
        });

        // 파일/폴더 목록
        app.MapGet("/api/drive/list", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            try
            {
                int? parentId = null;
                if (int.TryParse(ctx.Request.Query["parentId"], out int pid)) parentId = pid;

                var files = drive.ListFiles(userId.Value, parentId);
                var breadcrumb = drive.GetBreadcrumb(userId.Value, parentId);

                return Results.Json(new
                {
                    files = files.Select(f => new
                    {
                        f.Id, f.FileName, f.FileSize, f.IsFolder, f.ParentId, f.IsStarred,
                        createdAt = f.CreatedAt.ToString("o"),
                        updatedAt = f.UpdatedAt.ToString("o")
                    }),
                    breadcrumb = breadcrumb.Select(b => new { b.Id, b.Name })
                });
            }
            catch (Exception ex)
            {
                // 상세 오류는 서버 로그에만 남기고, 화면에는 일반 문구만 (내부 구조 노출 방지)
                Console.WriteLine("[Drive] 목록 조회 실패: " + ex);
                return Results.Json(new { error = "목록을 불러오지 못했습니다." }, statusCode: 500);
            }
        });

        // 폴더 생성
        app.MapPost("/api/drive/mkdir", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            string name = json.RootElement.GetProperty("name").GetString() ?? "새 폴더";
            // 경로 탐색·특수문자 제거 (보안)
            name = DriveService.SanitizeFileName(name);
            int? parentId = json.RootElement.TryGetProperty("parentId", out var p) && p.ValueKind != System.Text.Json.JsonValueKind.Null
                ? p.GetInt32() : null;
            if (!drive.IsOwnFolder(userId.Value, parentId)) return Results.BadRequest();

            int folderId = drive.CreateFolder(userId.Value, name, parentId);
            return Results.Json(new { id = folderId });
        });

        // 파일 업로드 (단일 — 소용량 파일)
        // 중복 파일명 체크
        app.MapGet("/api/drive/check-dup", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            try
            {
                string fileName = ctx.Request.Query["name"].FirstOrDefault() ?? "";
                int? parentId = int.TryParse(ctx.Request.Query["parentId"], out int p) ? p : null;

                int? dupId = drive.FindDuplicate(userId.Value, fileName, parentId);
                return Results.Json(new { exists = dupId != null, dupId });
            }
            catch (Exception ex)
            {
                // 내부 오류 내용은 서버 로그에만
                Console.WriteLine("[Drive] 중복 확인 실패: " + ex);
                return Results.Json(new { error = "확인하지 못했습니다." }, statusCode: 500);
            }
        });

        // 파일 업로드 — mode=overwrite(덮어쓰기), mode=rename(자동 번호), 기본=그냥 등록
        app.MapPost("/api/drive/upload", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            try
            {
                var form = await ctx.Request.ReadFormAsync();
                var file = form.Files.GetFile("file");
                if (file == null) return Results.BadRequest("파일 없음");

                int? parentId = null;
                if (form.TryGetValue("parentId", out var pv) && int.TryParse(pv, out int pid)) parentId = pid;
                if (!drive.IsOwnFolder(userId.Value, parentId)) return Results.BadRequest("잘못된 폴더");
                if (!drive.StorageOnline(userId.Value)) return StorageOffline();

                string mode = form["mode"].FirstOrDefault() ?? "";
                // 파일명 보안 정리 (경로 탐색·XSS 방지)
                string finalName = DriveService.SanitizeFileName(file.FileName);

                if (mode == "overwrite")
                {
                    int? dupId = drive.FindDuplicate(userId.Value, finalName, parentId);
                    if (dupId != null)
                    {
                        long oldSize = drive.GetFile(userId.Value, dupId.Value)?.FileSize ?? 0;
                        if (drive.WouldExceedQuota(userId.Value, file.Length, oldSize)) return QuotaExceeded();
                        string oPath = drive.GetPhysicalPath(userId.Value, dupId.Value);
                        Directory.CreateDirectory(Path.GetDirectoryName(oPath)!);
                        using var s = new FileStream(oPath, FileMode.Create);
                        await file.CopyToAsync(s);
                        drive.UpdateFileSize(userId.Value, dupId.Value, file.Length);
                        return Results.Json(new { id = dupId.Value, overwritten = true });
                    }
                }
                else if (mode == "rename")
                {
                    finalName = drive.GetUniqueName(userId.Value, finalName, parentId);
                }

                if (drive.WouldExceedQuota(userId.Value, file.Length)) return QuotaExceeded();
                int fileId = drive.RegisterFile(userId.Value, finalName, file.Length, parentId);
                string path = drive.GetPhysicalPath(userId.Value, fileId);
                try
                {
                    // 사용자 저장 디렉토리 자동 생성 (첫 업로드 시 필요)
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    using var stream = new FileStream(path, FileMode.Create);
                    await file.CopyToAsync(stream);
                }
                catch
                {
                    // 쓰다가 실패하면 DB 기록도 지워 '파일 없는 항목'이 용량을 차지하지 않게
                    drive.Delete(userId.Value, fileId);
                    try { File.Delete(path); } catch { }
                    throw;
                }

                return Results.Json(new { id = fileId, fileName = finalName });
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Drive] 업로드 실패: " + ex);
                return Results.Json(new { error = "업로드 중 오류가 발생했습니다." }, statusCode: 500);
            }
        }).DisableAntiforgery();

        // ── 청크 업로드 (대용량 파일) ──────────────────────────────────
        // 예전엔 조각을 임시 폴더에 모았다가 완료 때 다시 읽어 합쳐서 디스크에 같은 데이터를 두 번 썼음
        // (5GB 업로드 = 쓰기 10GB + 읽기 5GB → 버스 전원 USB 디스크가 버티지 못하고 끊기는 원인 중 하나)
        // 지금: 시작할 때 사용자 폴더 안에 최종 크기의 '.upload-{id}' 파일을 만들고, 조각을 받는 즉시 제 위치(offset)에 씀.
        //       완료하면 같은 디스크 안에서 이름만 바꿔(File.Move) 최종 파일이 됨 → 쓰기 1번, 합치기 없음
        var _uploads = new System.Collections.Concurrent.ConcurrentDictionary<string, (int UserId, string FileName, long FileSize, int TotalChunks, int? ParentId, string Mode, HashSet<int> Done)>();
        // uploadId → 조각 크기 (마지막 조각만 더 작음)
        var _uploadChunk = new System.Collections.Concurrent.ConcurrentDictionary<string, long>();
        // 업로드 중인 파일 경로 (최종 파일과 같은 폴더 = 같은 디스크라 완료 시 이름만 바꾸면 됨)
        string PartPath(DriveService drive, int userId, string uploadId) => Path.Combine(drive.EnsureUserDir(userId), ".upload-" + uploadId);

        // 업로드 시작 — uploadId 발급 + 최종 크기 파일 미리 만들기
        app.MapPost("/api/drive/upload/start", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            string fileName = json.RootElement.GetProperty("fileName").GetString() ?? "file";
            long fileSize = json.RootElement.GetProperty("fileSize").GetInt64();
            int totalChunks = json.RootElement.GetProperty("totalChunks").GetInt32();
            long chunkSize = json.RootElement.TryGetProperty("chunkSize", out var cs) ? cs.GetInt64() : 0;
            int? parentId = json.RootElement.TryGetProperty("parentId", out var p) && p.ValueKind != System.Text.Json.JsonValueKind.Null
                ? p.GetInt32() : null;
            string mode = json.RootElement.TryGetProperty("mode", out var m) ? m.GetString() ?? "" : "";

            // 입력값 유효성 검증 (비정상 요청 차단): 조각 크기 1~100MB, 조각 수가 크기와 맞아야 함
            if (fileSize <= 0 || chunkSize < 1024 * 1024 || chunkSize > 100L * 1024 * 1024 ||
                totalChunks <= 0 || totalChunks > 50000 || (fileSize + chunkSize - 1) / chunkSize != totalChunks)
                return Results.BadRequest("잘못된 업로드 파라미터");
            fileName = DriveService.SanitizeFileName(fileName);
            if (!drive.IsOwnFolder(userId.Value, parentId)) return Results.BadRequest("잘못된 폴더");
            if (!drive.StorageOnline(userId.Value)) return StorageOffline();
            // 진행 중인 업로드도 용량에 셈 — 여러 개를 동시에 시작해 한도를 넘기는 것 방지 (완료 단계에서 한 번 더 확인)
            // shortcut: 화면에서 업로드를 취소해도 서버 기록은 1시간 정리 타이머가 지울 때까지 용량·개수에 잡힘 — 불편 신고가 오면 취소 API를 추가할 것
            var mine = _uploads.Values.Where(u => u.UserId == userId.Value).ToList();
            if (mine.Count >= 6) return Results.Json(new { error = "busy", message = "동시에 올릴 수 있는 파일이 너무 많습니다. 잠시 후 다시 시도해 주세요." }, statusCode: 429);
            if (drive.WouldExceedQuota(userId.Value, fileSize + mine.Sum(u => u.FileSize))) return QuotaExceeded();

            string dir = drive.EnsureUserDir(userId.Value);
            Directory.CreateDirectory(dir);
            // 서버 재시작 등으로 버려진 하루 넘은 업로드 파일 정리
            foreach (var old in Directory.EnumerateFiles(dir, ".upload-*"))
                try { if ((DateTime.UtcNow - File.GetLastWriteTimeUtc(old)).TotalDays > 1) File.Delete(old); } catch { }

            string uploadId = Guid.NewGuid().ToString("N");
            // 최종 크기로 미리 만듦 (ext4에선 빈 공간을 실제로 쓰지 않는 sparse 파일이라 즉시 끝남)
            using (var fs = new FileStream(PartPath(drive, userId.Value, uploadId), FileMode.CreateNew))
                fs.SetLength(fileSize);
            _uploadChunk[uploadId] = chunkSize;
            _uploads[uploadId] = (userId.Value, fileName, fileSize, totalChunks, parentId, mode, new HashSet<int>());

            return Results.Json(new { uploadId });
        });

        // 청크 수신 — 받은 조각을 최종 파일의 제 위치에 바로 씀
        app.MapPost("/api/drive/upload/chunk", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            var form = await ctx.Request.ReadFormAsync();
            string uploadId = form["uploadId"].ToString();
            if (!int.TryParse(form["chunkIndex"].ToString(), out int chunkIndex))
                return Results.BadRequest("잘못된 청크 인덱스");
            var chunk = form.Files.GetFile("chunk");
            if (chunk == null || !_uploads.TryGetValue(uploadId, out var meta) || !_uploadChunk.TryGetValue(uploadId, out long chunkSize))
                return Results.BadRequest();
            if (meta.UserId != userId.Value) return Results.Forbid();
            if (chunkIndex < 0 || chunkIndex >= meta.TotalChunks) return Results.BadRequest("청크 인덱스 범위 초과");

            // 조각 크기가 정확해야 함 (마지막만 남은 크기) → 신고 크기보다 많이 써서 용량을 우회할 수 없음
            long offset = chunkIndex * chunkSize;
            if (chunk.Length != Math.Min(chunkSize, meta.FileSize - offset))
                return Results.BadRequest("조각 크기가 맞지 않습니다.");

            // 여러 조각이 동시에 같은 파일의 다른 위치에 씀 (FileShare.ReadWrite)
            using (var fs = new FileStream(PartPath(drive, userId.Value, uploadId), FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
            {
                fs.Seek(offset, SeekOrigin.Begin);
                await chunk.CopyToAsync(fs);
            }
            lock (meta.Done) meta.Done.Add(chunkIndex);   // 동시 요청이 같은 HashSet을 건드리므로 잠금
            return Results.Ok();
        }).DisableAntiforgery();

        // 청크 업로드 완료 — 빠진 조각이 없으면 이름만 바꿔 최종 파일로
        app.MapPost("/api/drive/upload/complete", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            string uploadId = json.RootElement.GetProperty("uploadId").GetString() ?? "";

            if (!_uploads.TryRemove(uploadId, out var meta)) return Results.BadRequest();
            _uploadChunk.TryRemove(uploadId, out _);
            if (meta.UserId != userId.Value) return Results.Forbid();

            string part = PartPath(drive, userId.Value, uploadId);
            void Drop() { try { File.Delete(part); } catch { } }
            int received; lock (meta.Done) received = meta.Done.Count;
            if (received != meta.TotalChunks || !File.Exists(part)) { Drop(); return Results.BadRequest("빠진 조각이 있습니다. 다시 올려 주세요."); }

            // 덮어쓰기 모드: 기존 파일 자리로 이름만 바꿈
            string finalName = meta.FileName;
            if (meta.Mode == "overwrite")
            {
                int? dupId = drive.FindDuplicate(userId.Value, meta.FileName, meta.ParentId);
                if (dupId != null)
                {
                    long oldSize = drive.GetFile(userId.Value, dupId.Value)?.FileSize ?? 0;
                    if (drive.WouldExceedQuota(userId.Value, meta.FileSize, oldSize)) { Drop(); return QuotaExceeded(); }
                    File.Move(part, drive.GetPhysicalPath(userId.Value, dupId.Value), overwrite: true);
                    drive.UpdateFileSize(userId.Value, dupId.Value, meta.FileSize);
                    return Results.Json(new { id = dupId.Value, overwritten = true });
                }
            }
            else if (meta.Mode == "rename")
            {
                finalName = drive.GetUniqueName(userId.Value, meta.FileName, meta.ParentId);
            }

            // 용량 확인 → DB 등록 → 이름 바꾸기 (실패하면 DB 기록도 지워 유령 파일이 남지 않게)
            if (drive.WouldExceedQuota(userId.Value, meta.FileSize)) { Drop(); return QuotaExceeded(); }
            int fileId = drive.RegisterFile(userId.Value, finalName, meta.FileSize, meta.ParentId);
            try { File.Move(part, drive.GetPhysicalPath(userId.Value, fileId), overwrite: true); }
            catch (Exception ex)
            {
                drive.Delete(userId.Value, fileId); Drop();
                Console.WriteLine("[Drive] 업로드 완료 처리 실패: " + ex);
                return Results.Json(new { error = "업로드를 마무리하지 못했습니다." }, statusCode: 500);
            }
            return Results.Json(new { id = fileId, fileName = finalName });
        });

        // 파일 다운로드 — 인라인 미리보기 시 안전한 MIME 타입만 허용 (XSS 차단)
        app.MapGet("/api/drive/download/{id:int}", (int id, HttpContext ctx, DriveService drive) =>
        {
            // Header 토큰 우선, 쿼리 파라미터는 폴백 (로그 노출 최소화)
            int? userId = DriveAuth(ctx, drive);
            if (userId == null)
            {
                string? token = ctx.Request.Query["token"].FirstOrDefault();
                userId = drive.ValidateTokenFor(token, ctx.Session.GetString("UserID"));
            }
            if (userId == null) return Results.Unauthorized();

            var file = drive.GetFile(userId.Value, id);
            if (file == null || file.IsFolder) return Results.NotFound();

            string path = drive.GetPhysicalPath(userId.Value, id);
            if (!File.Exists(path)) return Results.NotFound();

            // inline=1 이면 브라우저 미리보기용 (Content-Disposition: inline)
            bool inline = ctx.Request.Query["inline"] == "1";
            string contentType = GetMimeType(file.FileName);

            if (inline)
            {
                // HTML/SVG/XML 등 스크립트 실행 가능한 타입은 인라인 차단 (Stored XSS 방지)
                var safeInlineTypes = new HashSet<string> {
                    "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp",
                    "video/mp4", "video/webm", "video/quicktime", "video/x-msvideo", "video/x-matroska",
                    "audio/mpeg", "audio/wav", "audio/ogg", "audio/flac", "audio/aac", "audio/mp4",
                    "application/pdf", "text/plain"
                };
                if (!safeInlineTypes.Contains(contentType))
                    contentType = "application/octet-stream";
                return Results.File(path, contentType, enableRangeProcessing: true);
            }
            return Results.File(path, contentType, file.FileName);
        });

        // 파일/폴더 삭제
        app.MapDelete("/api/drive/delete/{id:int}", (int id, HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            // 폴더면 하위 파일들의 물리 파일도 삭제
            var item = drive.GetFile(userId.Value, id);
            if (item == null) return Results.NotFound();

            if (item.IsFolder)
            {
                var childIds = drive.GetAllFileIdsInFolder(userId.Value, id);
                foreach (int cid in childIds)
                {
                    string cpath = drive.GetPhysicalPath(userId.Value, cid);
                    try { if (File.Exists(cpath)) File.Delete(cpath); } catch { }
                }
            }
            else
            {
                string path = drive.GetPhysicalPath(userId.Value, id);
                try { if (File.Exists(path)) File.Delete(path); } catch { }
            }

            drive.Delete(userId.Value, id);
            return Results.Ok();
        });

        // 이름 변경
        app.MapPost("/api/drive/rename", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            int fileId = json.RootElement.GetProperty("id").GetInt32();
            string newName = json.RootElement.GetProperty("newName").GetString() ?? "";
            // 경로 탐색·특수문자 제거 (보안)
            newName = DriveService.SanitizeFileName(newName);

            if (string.IsNullOrWhiteSpace(newName)) return Results.BadRequest();
            drive.Rename(userId.Value, fileId, newName);
            return Results.Ok();
        });

        // 파일/폴더 이동
        app.MapPost("/api/drive/move", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            int fileId = json.RootElement.GetProperty("id").GetInt32();
            int? newParentId = json.RootElement.TryGetProperty("newParentId", out var p) && p.ValueKind != System.Text.Json.JsonValueKind.Null
                ? p.GetInt32() : null;

            bool ok = drive.Move(userId.Value, fileId, newParentId);
            return ok ? Results.Ok() : Results.BadRequest();
        });

        // 즐겨찾기 토글
        app.MapPost("/api/drive/star", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            int fileId = json.RootElement.GetProperty("id").GetInt32();

            bool starred = drive.ToggleStar(userId.Value, fileId);
            return Results.Json(new { starred });
        });

        // 즐겨찾기 목록
        app.MapGet("/api/drive/starred", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            var files = drive.ListStarred(userId.Value);
            return Results.Json(new
            {
                files = files.Select(f => new
                {
                    f.Id, f.FileName, f.FileSize, f.IsFolder, f.ParentId, f.IsStarred,
                    createdAt = f.CreatedAt.ToString("o"),
                    updatedAt = f.UpdatedAt.ToString("o")
                })
            });
        });

        // 검색
        app.MapGet("/api/drive/search", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            string query = ctx.Request.Query["q"].FirstOrDefault() ?? "";
            // 검색 쿼리 길이 제한 (과도한 DB 부하 방지)
            if (string.IsNullOrWhiteSpace(query) || query.Length > 200)
                return Results.Json(new { files = Array.Empty<object>() });

            var files = drive.Search(userId.Value, query);
            return Results.Json(new
            {
                files = files.Select(f => new
                {
                    f.Id, f.FileName, f.FileSize, f.IsFolder, f.ParentId, f.IsStarred,
                    createdAt = f.CreatedAt.ToString("o"),
                    updatedAt = f.UpdatedAt.ToString("o")
                })
            });
        });

        // 최근 파일
        app.MapGet("/api/drive/recent", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            var files = drive.ListRecent(userId.Value);
            return Results.Json(new
            {
                files = files.Select(f => new
                {
                    f.Id, f.FileName, f.FileSize, f.IsFolder, f.ParentId, f.IsStarred,
                    createdAt = f.CreatedAt.ToString("o"),
                    updatedAt = f.UpdatedAt.ToString("o")
                })
            });
        });

        // 휴지통으로 이동 (소프트 삭제)
        app.MapPost("/api/drive/trash/{id:int}", (int id, HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();
            drive.Trash(userId.Value, id);
            return Results.Ok();
        });

        // 휴지통에서 복원
        app.MapPost("/api/drive/restore/{id:int}", (int id, HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();
            drive.Restore(userId.Value, id);
            return Results.Ok();
        });

        // 휴지통 목록
        app.MapGet("/api/drive/trash", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            var files = drive.ListTrash(userId.Value);
            return Results.Json(new
            {
                files = files.Select(f => new
                {
                    f.Id, f.FileName, f.FileSize, f.IsFolder, f.ParentId, f.IsStarred,
                    createdAt = f.CreatedAt.ToString("o"),
                    updatedAt = f.UpdatedAt.ToString("o"),
                    trashedAt = f.TrashedAt?.ToString("o")
                })
            });
        });

        // 휴지통 비우기 (영구 삭제)
        app.MapDelete("/api/drive/trash/empty", (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            // 물리 파일 삭제
            var fileIds = drive.GetTrashFileIds(userId.Value);
            foreach (int fid in fileIds)
            {
                string path = drive.GetPhysicalPath(userId.Value, fid);
                try { if (File.Exists(path)) File.Delete(path); } catch { }
            }
            drive.EmptyTrash(userId.Value);
            return Results.Ok();
        });

        // 파일 복사
        app.MapPost("/api/drive/copy", async (HttpContext ctx, DriveService drive) =>
        {
            int? userId = DriveAuth(ctx, drive);
            if (userId == null) return Results.Unauthorized();

            using var reader = new StreamReader(ctx.Request.Body);
            var json = System.Text.Json.JsonDocument.Parse(await reader.ReadToEndAsync());
            int fileId = json.RootElement.GetProperty("id").GetInt32();
            var srcItem = drive.GetFile(userId.Value, fileId);
            if (srcItem == null || srcItem.IsFolder) return Results.BadRequest();
            if (!drive.StorageOnline(userId.Value)) return StorageOffline();
            if (drive.WouldExceedQuota(userId.Value, srcItem.FileSize)) return QuotaExceeded();

            int? newId = drive.CopyFile(userId.Value, fileId);
            if (newId == null) return Results.BadRequest();

            // 물리 파일 복사 — 실패하면 방금 만든 DB 기록을 지움 (파일 없는 항목 방지)
            string src = drive.GetPhysicalPath(userId.Value, fileId);
            string dst = drive.GetPhysicalPath(userId.Value, newId.Value);
            try { File.Copy(src, dst); }
            catch (Exception ex)
            {
                drive.Delete(userId.Value, newId.Value);
                Console.WriteLine("[Drive] 복사 실패: " + ex.Message);
                return Results.Json(new { error = "복사하지 못했습니다." }, statusCode: 500);
            }

            return Results.Json(new { id = newId });
        });

        // ── 드라이브 관리자 API (사이트 관리자만) ──────────────────────────
        // 운영·안전(불법 파일 대응)을 위해 회원 드라이브를 열람·삭제. 개인정보처리방침에 고지함

        // 회원별 사용량 목록
        app.MapGet("/api/drive/admin/users", (HttpContext ctx, DriveService drive) =>
        {
            if (DriveAdminAuth(ctx, drive) == null) return Results.Unauthorized();
            return Results.Json(new { users = drive.ListUsersWithUsage(), quota = DriveService.MEMBER_QUOTA });
        });

        // 회원별 용량 한도 바꾸기 — { user: 드라이브 계정 id, gb: 1~1000 정수 또는 null(기본 5GB로) }
        app.MapPost("/api/drive/admin/quota", async (HttpContext ctx, DriveService drive) =>
        {
            if (DriveAdminAuth(ctx, drive) == null) return Results.Unauthorized();
            var body = await ctx.Request.ReadFromJsonAsync<System.Text.Json.JsonElement>();
            if (!body.TryGetProperty("user", out var u) || !u.TryGetInt32(out int target)) return Results.BadRequest();
            long? bytes = null;
            if (body.TryGetProperty("gb", out var g) && g.ValueKind != System.Text.Json.JsonValueKind.Null)
            {
                // 정수 GB만, 1~1000 (디스크보다 큰 값·음수·소수 같은 실수 방지)
                if (!g.TryGetInt32(out int gb) || gb < 1 || gb > 1000) return Results.BadRequest(new { error = "1~1000 사이 정수(GB)로 입력하세요." });
                bytes = gb * 1024L * 1024 * 1024;
            }
            if (!drive.SetQuota(target, bytes)) return Results.NotFound();
            Console.WriteLine($"[Drive] 관리자 용량 변경: user={target} quota={(bytes == null ? "기본" : bytes / (1024L * 1024 * 1024) + "GB")}");
            return Results.Json(new { ok = true, quota = bytes ?? DriveService.MEMBER_QUOTA });
        });

        // 회원 드라이브의 폴더 내용
        app.MapGet("/api/drive/admin/list", (HttpContext ctx, DriveService drive) =>
        {
            if (DriveAdminAuth(ctx, drive) == null) return Results.Unauthorized();
            if (!int.TryParse(ctx.Request.Query["user"], out int target)) return Results.BadRequest();
            int? folder = int.TryParse(ctx.Request.Query["folder"], out int f) ? f : null;
            return Results.Json(new
            {
                username = drive.GetUsername(target),
                files = drive.ListFiles(target, folder),
                breadcrumb = drive.GetBreadcrumb(target, folder).Select(b => new { id = b.Id, name = b.Name })
            });
        });

        // 회원 파일 내려받기 (새 탭 링크용으로 쿼리 토큰도 허용, 역시 관리자 본인 세션이어야 함)
        app.MapGet("/api/drive/admin/download/{user:int}/{id:int}", (int user, int id, HttpContext ctx, DriveService drive) =>
        {
            int? admin = DriveAdminAuth(ctx, drive);
            if (admin == null)
            {
                int? u = drive.ValidateTokenFor(ctx.Request.Query["token"].FirstOrDefault(), ctx.Session.GetString("UserID"));
                admin = u != null && drive.IsAdmin(u.Value) ? u : null;
            }
            if (admin == null) return Results.Unauthorized();
            var file = drive.GetFile(user, id);
            if (file == null || file.IsFolder) return Results.NotFound();
            string path = drive.GetPhysicalPath(user, id);
            if (!File.Exists(path)) return Results.NotFound();
            return Results.File(path, "application/octet-stream", file.FileName);   // 관리자 화면에선 미리보기 없이 내려받기만 (XSS 방지)
        });

        // 회원 파일·폴더 삭제 (휴지통을 거치지 않고 바로 삭제)
        app.MapDelete("/api/drive/admin/delete/{user:int}/{id:int}", (int user, int id, HttpContext ctx, DriveService drive) =>
        {
            if (DriveAdminAuth(ctx, drive) == null) return Results.Unauthorized();
            var item = drive.GetFile(user, id);
            if (item == null) return Results.NotFound();
            var ids = item.IsFolder ? drive.GetAllFileIdsInFolder(user, id) : new[] { id };
            foreach (int cid in ids)
            {
                string cpath = drive.GetPhysicalPath(user, cid);
                try { if (File.Exists(cpath)) File.Delete(cpath); } catch { }
            }
            drive.Delete(user, id);
            Console.WriteLine($"[Drive] 관리자 삭제: user={user} id={id} name={item.FileName}");
            return Results.Ok();
        });

        // MIME 타입 매핑 헬퍼
        static string GetMimeType(string fileName)
        {
            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            return ext switch
            {
                ".jpg" or ".jpeg" => "image/jpeg",
                ".png" => "image/png",
                ".gif" => "image/gif",
                ".webp" => "image/webp",
                ".svg" => "image/svg+xml",
                ".bmp" => "image/bmp",
                ".ico" => "image/x-icon",
                ".mp4" => "video/mp4",
                ".webm" => "video/webm",
                ".mov" => "video/quicktime",
                ".avi" => "video/x-msvideo",
                ".mkv" => "video/x-matroska",
                ".mp3" => "audio/mpeg",
                ".wav" => "audio/wav",
                ".ogg" => "audio/ogg",
                ".flac" => "audio/flac",
                ".aac" => "audio/aac",
                ".m4a" => "audio/mp4",
                ".pdf" => "application/pdf",
                ".json" => "application/json",
                ".xml" => "application/xml",
                ".zip" => "application/zip",
                ".html" or ".htm" => "text/html",
                ".css" => "text/css",
                ".js" => "text/javascript",
                ".txt" or ".md" or ".csv" or ".log" => "text/plain",
                ".py" or ".cs" or ".java" or ".go" or ".rs" or ".rb" or ".php" or ".sh" or ".yml" or ".yaml" or ".sql" or ".ts" or ".tsx" or ".jsx" => "text/plain",
                _ => "application/octet-stream"
            };
        }

        // ── 정리 타이머(10분마다): 1시간 넘게 조각이 오지 않은 업로드 파일 + 만료된 드라이브 세션 ──
        _cleanup = new System.Threading.Timer(_ =>
        {
            var now = DateTime.UtcNow;
            try
            {
                var drv = app.Services.GetRequiredService<DriveService>();
                foreach (var kv in _uploads.ToArray())
                {
                    string part = PartPath(drv, kv.Value.UserId, kv.Key);
                    if (File.Exists(part) && (now - File.GetLastWriteTimeUtc(part)).TotalHours <= 1) continue;
                    _uploads.TryRemove(kv.Key, out var _gone1);   // 타이머 인자 이름이 _ 라서 버림(_) 대신 변수로 받음
                    _uploadChunk.TryRemove(kv.Key, out var _gone2);
                    try { File.Delete(part); } catch { }
                }
            }
            catch { }
            try { app.Services.GetRequiredService<DriveService>().CleanExpiredSessions(); } catch { }
        }, null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));
    }

    // 타이머가 가비지 컬렉션으로 사라지지 않게 붙잡아 둠
    private static System.Threading.Timer _cleanup;
}
