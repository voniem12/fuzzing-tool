import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
# urlparse(url) tách url thành 6 phần
# parse_qs chuyển nó thành dạng dict
# urljoin kiểu nó sẽ ghép url gốc với url tương đối
class WebCrawler:
    def __init__(self, start_url, cookies=None):
        self.start_url = start_url
        self.crawled_urls = set()# set dùng để lưu trữ danh dánh nhg nó nhanh hơn list, và loại bỏ trùng lặp
        self.cookies = cookies
        self.urls_with_params = set()
        self.forms = []
        self.base_domain = urlparse(start_url).netloc

    def crawl(self, max_depth=5):
        self._crawl_url(self.start_url, 0, max_depth)
        return sorted(list(self.urls_with_params)), self.forms # list(self.urls_with_params) đảm bảo kết quả lưu lại theo danh sách, và sắp xếp

    def _crawl_url(self, url, depth, max_depth):
        if url in self.crawled_urls or depth > max_depth:# url đã crawl rồi thì sẽ k crawl nữa or depth quá cx thôi
            return

        print(f"Crawling {url}")
        self.crawled_urls.add(url)

        if self._has_parameters(url):
            self.urls_with_params.add(self._normalize_url(url))

        try:
            response = requests.get(url, cookies=self.cookies, timeout=10) # Gửi request GET với timeout 10 giây
            if not response.ok:#  # Kiểm tra xem response có thành công không
                print(f"HTTP Error {response.status_code} for {url}")# In mã lỗi HTTP nếu có
                return

            soup = BeautifulSoup(response.text, 'html.parser')# cấu trúc cây (tree structure) 

            # Tìm kiếm tất cả các form trong trang
            for form in soup.find_all("form"):
                self.forms.append(self._extract_form_info(url, form))

            # Tìm tất cả các liên kết trong trang
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])# ghép cái url với cái đường dẫn tương đối trong href
                if urlparse(full_url).netloc == self.base_domain:# kiểm tra xem có cùng domain không
                    self._crawl_url(full_url, depth + 1, max_depth)# cái full_url lại làm đầu vào tiếp, độ delth tăng 1 

        except Exception as e:
            print(f"Error crawling {url}: {e}")

    def _has_parameters(self, url):
        return '?' in url

    def _normalize_url(self, url):
        parsed = urlparse(url)
        path = parsed.path
        query_params = [f"{param}=" for param in sorted(parse_qs(parsed.query).keys())]# lấy phần query xong chuyển nó sang dạng dict rồi sắp xếp theo abc rồi in nó ra kiểu id=
        return f"{parsed.scheme}://{parsed.netloc}{path}?{'&'.join(query_params)}" if query_params else f"{parsed.scheme}://{parsed.netloc}{path}"

  

    def _extract_form_info(self, url, form):
        action = form.get("action", "").strip()  # Lấy action, mặc định là ""
        full_url = urljoin(url, action) if action else url  # Ghép URL đầy đủ
        method = form.get("method", "GET").upper()

        # Lấy tất cả input và button (tránh bỏ sót nút submit)
        inputs = {}
        for input_tag in form.find_all(["input", "button"]):
            name = input_tag.get("name", "")
            input_type = input_tag.get("type", "text")  # Mặc định là text
            inputs[name] = input_type

        print(f"[DEBUG] Form found -> URL: {full_url}, Action: {action}, Method: {method}, Inputs: {inputs}")

        return {"url": full_url, "method": method, "inputs": inputs}

                #         {
            #         "url": "https://example.com/login",
            #         "method": "POST",
            #         "inputs": {
            #             "username": "text",
            #             "password": "password",
            #             "csrf_token": "hidden"
            #         }
            # }