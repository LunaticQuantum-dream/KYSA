package db

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const (
	LOOPHOLE_PATCH_URL = `https://www.kylinos.cn/support/loophole/patch.html`
	// example: https://www.kylinos.cn/support/loophole/patch/8035.html
	LOOPHOLE_PATCH_DETAIL_URL = `https://www.kylinos.cn`
)

type KYSAReport struct {
	Name       string
	Severity   string
	Descrition string
	Published  string
	URL        string
}

type KYSAPatchDetail struct {
	KYSAReport
	Title  string
	Detail string
}

func (patch *KYSAPatchDetail) String() string {
	return fmt.Sprintf(
		"Name:%s\nSeverity:%s\nSummary:%s\nPublished:%s\nURL:%s\nTitle:%s\n%s\n",
		patch.Name,
		patch.Severity,
		patch.Descrition,
		patch.Published,
		patch.URL,
		patch.Title,
		patch.Detail,
	)
}

func GenerateReport(doc *goquery.Document) []KYSAReport {
	ret := make([]KYSAReport, 0)

	// Find the line items
	doc.Find(".layui-table").Each(func(i int, s *goquery.Selection) {
		//fmt.Printf("lines=%s\n", s.Text())
		s.Find("tbody").Each(func(j int, ss *goquery.Selection) {
			ss.Find("tr").Each(func(k int, sss *goquery.Selection) {
				data := make([]string, 0)
				url := ""
				sss.Find("td").Each(func(l int, td *goquery.Selection) {
					tdText := strings.TrimSpace(td.Text())
					data = append(data, tdText)
					if strings.HasPrefix(tdText, "KYSA") || strings.HasPrefix(tdText, "CVE") || strings.HasPrefix(tdText, "YSA") || strings.HasPrefix(tdText, "KSN") || strings.HasPrefix(tdText, "CS2CSA") {
						if val, ok := td.Find("a").First().Attr("href"); ok {
							fmt.Printf("href=%s\n", val)
							url = val
						}
					}
				})
				fmt.Printf("data=%#v\n", data)
				if len(data) == 5 {
					ret = append(ret, KYSAReport{
						Name:       data[1],
						Severity:   data[2],
						Descrition: data[3],
						Published:  data[4],
						URL:        url,
					})
				}
			})
		})
	})
	return ret
}

func ParseCVE(cve string) []KYSAReport {
	url := fmt.Sprintf("%s?impact=&query_key=%s", LOOPHOLE_PATCH_URL, cve)

	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	return GenerateReport(doc)
}

func ParsePage(pageIndex int) []KYSAReport {
	url := fmt.Sprintf("%s?page=%d", LOOPHOLE_PATCH_URL, pageIndex)
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	return GenerateReport(doc)
}

func ParseKYSAReport(report *KYSAReport) *KYSAPatchDetail {
	url := fmt.Sprintf("%s%s", LOOPHOLE_PATCH_DETAIL_URL, report.URL)
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	data := make([]string, 0)
	doc.Find(".base-desc").Each(func(i int, s *goquery.Selection) {
		data = append(data, s.Text())
	})

	if len(data) == 2 {
		return &KYSAPatchDetail{
			KYSAReport: KYSAReport{
				Name:       report.Name,
				Severity:   report.Severity,
				Descrition: report.Descrition,
				Published:  report.Published,
				URL:        report.URL,
			},
			Title:  data[0],
			Detail: data[1],
		}
	}
	return nil
}
