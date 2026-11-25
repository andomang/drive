# Cloud Drive

domang 통합 계정으로 로그인하면 회원마다 개인 저장 공간을 주는 클라우드 드라이브입니다. 라즈베리파이 서버에서 직접 운영합니다.

**[사용하기](https://domang.org/drive)** · [소개 페이지](https://domang.org/driveindex)

## 기능

- 회원마다 5GB (관리자가 회원별로 조절 가능), 휴지통 포함
- 대용량 업로드: 20MB 조각을 받는 즉시 제자리에 한 번만 써서 디스크 부담을 줄임
- 폴더, 즐겨찾기, 최근 파일, 휴지통, 검색, 이름 변경·이동·복사, 미리보기
- 보안: 본인 파일만 조회, 폴더 고리·남의 폴더 번호 차단, 용량 우회(휴지통·동시 업로드) 차단, 실행 가능한 형식은 미리보기 금지

## 파일

| 파일 | 내용 |
|---|---|
| `DriveApi.cs` | `/api/drive/*` API 전부 (업로드·다운로드·폴더·휴지통·관리자) |
| `Services/DriveService.cs` | DB(PostgreSQL)·디스크 저장, 용량 계산 |
| `Pages/Drive*.cshtml` | 입구(로그인), 파일 화면, 소개 페이지 |

이 저장소는 domang.org 서버(ASP.NET Core 8) 중 드라이브 부분만 옮긴 것이라 단독으로는 빌드되지 않습니다. 전체 서버는 [andomang/domang](https://github.com/andomang/domang) 에 있습니다.
