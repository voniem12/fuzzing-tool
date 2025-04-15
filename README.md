# Công Cụ Quét Bảo Mật Web (Web Security Fuzzer)

Một công cụ kiểm tra bảo mật ứng dụng web đa năng hỗ trợ SQL injection, XSS (Cross-Site Scripting), và khả năng thu thập thông tin web.

## Tính Năng

- **Trình Thu Thập Web**: Khám phá các URL trên một trang web đích với độ sâu có thể cấu hình
- **Trình Quét SQL Injection**: Kiểm tra các lỗ hổng SQL injection trên các tham số URL
- **Trình Quét XSS**: Kiểm tra các lỗ hổng Cross-Site Scripting phản chiếu (Reflected XSS)
- **Linh Hoạt**: Hỗ trợ cho yêu cầu GET
- **Tùy Chỉnh**: Cấu hình headers, cookies, User-Agent và nhiều hơn nữa
- **Tạo Báo Cáo**: Lưu kết quả quét ở định dạng JSON

## Cài Đặt

1. Clone kho lưu trữ:

```
git clone https://github.com/yourusername/web-security-fuzzer.git
cd web-security-fuzzer
```

2. Cài đặt các gói phụ thuộc cần thiết:

```
pip install -r requirements.txt
```

## Cách Sử Dụng

### Sử Dụng Cơ Bản

```
python main.py -u "http://example.com/page.php?id=1" --sql
```

### Lựa Chọn Module

- Sử dụng `--sql` cho kiểm tra SQL injection
- Sử dụng `--xss` cho kiểm tra XSS
- Sử dụng `--crawl` cho thu thập thông tin web

### Ví Dụ

#### Quét SQL Injection Cơ Bản

```
python main.py -u "http://example.com/page.php?id=1" --sql
```

#### Thu Thập Thông Tin Trang Web và Kiểm Tra XSS Trên Các URL Đã Phát Hiện

```
python main.py -u "http://example.com/" --crawl --xss --depth 3
```

#### Chạy Tất Cả Các Loại Quét Với Đầu Ra Chi Tiết

```
python main.py -u "http://example.com/" --sql --xss --crawl -v -o results.json
```

### Tùy Chọn Thu Thập Thông Tin

```
--depth N              Độ sâu thu thập tối đa (mặc định: 2)
```

### Tùy Chọn SQL Injection

```
--params PARAMS        Xác định các tham số cần kiểm tra cho SQL injection (phân tách bằng dấu phẩy)
```

### Tùy Chọn Yêu Cầu

```
-H, --headers HEADERS  HTTP headers tùy chỉnh (ví dụ: 'Header1:value1,Header2:value2')
-c, --cookies COOKIES  HTTP cookies (ví dụ: 'cookie1=value1;cookie2=value2')
-A, --user-agent AGENT User-Agent tùy chỉnh
--no-verify-ssl        Tắt xác minh chứng chỉ SSL cho kết nối HTTPS
```

### Tùy Chọn Đầu Ra

```
-o, --output FILE      Lưu kết quả vào tệp (định dạng JSON)
-v, --verbose          Đầu ra chi tiết
--no-color             Tắt đầu ra có màu
```

## Tham Khảo Đầy Đủ Lệnh

```
python main.py [-h] -u URL [--sql] [--xss] [--crawl]
               [--depth DEPTH] [--params PARAMS]
               [-H HEADERS] [-c COOKIES] [-A USER_AGENT]
               [--no-verify-ssl] [-o OUTPUT] [-v] [--no-color]
```

## Ví Dụ

### Thu Thập Thông Tin Trang Web và Kiểm Tra SQL Injection

```
python main.py -u "http://testphp.vulnweb.com/" --crawl --sql --depth 2
```

### Quét Với Headers và Cookies Tùy Chỉnh

```
python main.py -u "http://example.com/page.php?id=1" --sql --xss --crawl -H "Referer:http://example.com/,X-Forwarded-For:127.0.0.1" -c "session=abc123;logged_in=true"
```

## Cấu Trúc Dự Án

```
web-security-fuzzer/
├── main.py                # Điểm vào chính
├── requirements.txt       # Các gói phụ thuộc Python
├── modules/               # Thư mục các module
│   ├── common/            # Tiện ích chung
│   │   ├── __init__.py
│   │   ├── request_handler.py
│   │   ├── url_parser.py
│   │   └── utils.py
│   ├── sql/               # Các module SQL injection
│   │   ├── __init__.py
│   │   ├── sql_scanner.py
│   │   ├── payload_generator.py
│   │   └── response_analyzer.py
│   ├── xss/               # Các module XSS
│   │   ├── __init__.py
│   │   ├── xss_scanner.py
│   │   └── payload_generator.py
│   └── crawler/           # Các module thu thập web
│       ├── __init__.py
│       └── crawler.py
```

## Tuyên Bố Miễn Trừ Trách Nhiệm

Công cụ này chỉ dành cho mục đích giáo dục và kiểm tra bảo mật được ủy quyền. Không sử dụng nó chống lại các trang web mà không có sự cho phép rõ ràng. Quét trái phép các trang web có thể là bất hợp pháp trong khu vực pháp lý của bạn.

## Giấy Phép

Dự án này được cấp phép theo Giấy Phép MIT - xem tệp LICENSE để biết chi tiết.

## Đóng Góp

Đóng góp luôn được hoan nghênh! Vui lòng gửi Pull Request.
