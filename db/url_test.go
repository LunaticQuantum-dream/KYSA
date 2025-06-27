package db

import (
	"reflect"
	"testing"
)

func TestParseCVE(t *testing.T) {
	type args struct {
		cve string
	}
	tests := []struct {
		name string
		args args
		want []KYSAReport
	}{
		{
			name: "",
			args: args{
				cve: "CVE-2025-4802",
			},
			want: []KYSAReport{
				{
					Name:       "KYSA-202506-1068",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8020.html",
				},
				{
					Name:       "KYSA-202506-1067",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8019.html",
				},
				{
					Name:       "KYSA-202506-1060",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8014.html",
				},
				{
					Name:       "KYSA-202506-1059",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8013.html",
				},
				{
					Name:       "KYSA-202506-1058",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8012.html",
				},
				{
					Name:       "KYSA-202506-1057",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8011.html",
				},
				{
					Name:     "KYSA-202506-1056",
					Severity: "重要", Descrition: "glibc安全漏洞",
					Published: "2025-06-17",
					URL:       "/support/loophole/patch/8010.html",
				},
				{
					Name:       "KYSA-202506-1055",
					Severity:   "重要",
					Descrition: "glibc安全漏洞",
					Published:  "2025-06-17",
					URL:        "/support/loophole/patch/8009.html",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseCVE(tt.args.cve); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCVE() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseKYSAReport(t *testing.T) {
	type args struct {
		report *KYSAReport
	}
	tests := []struct {
		name string
		args args
		want *KYSAPatchDetail
	}{
		{
			name: "patch 8035.html",
			args: args{
				report: &KYSAReport{
					Name:       "KYSA-202506-0002",
					Severity:   "严重",
					Descrition: "libblockdev安全漏洞",
					Published:  "2025-06-25",
					URL:        "/support/loophole/patch/8035.html",
				},
			},
			want: &KYSAPatchDetail{
				KYSAReport: KYSAReport{
					Name:       "KYSA-202506-0002",
					Severity:   "严重",
					Descrition: "libblockdev安全漏洞",
					Published:  "2025-06-25",
					URL:        "/support/loophole/patch/8035.html",
				},
				Title: "\n\t\t\t公告ID：KYSA-202506-0002\n公告 摘要：libblockdev安全漏洞\n等级：严重\n发布日期：2025-06-25\n\t\t", Detail: "注：\n1. 本公告所涉及的漏洞修复信息知识产权全部归麒麟软件有限公司所有，此安全漏洞补丁公告仅适用于麒麟软件操作系统通用主线产品，定制、OEM等版本可根据需要联系售后获取支持。任何媒体、网站或个人转载使用时不得进行商业性的原版原式的转载，也不得歪曲和篡改所发布的内容。此声明以及其修改权、更新权及最终解释权均归本网所有。\n2. 此安全漏洞补丁公告仅适用于银河麒麟桌面操作系统V10 SP1版本，系统版本查询工具下载链接：\nhttps://security-oss.kylinos.cn/Desktop/libkysdk-sysinfo.zip\n\n1. 漏 洞概述\nCVE-2025-6019\nStoraged libblockdev是Storaged开源的一个用于操纵块设备的库。Storaged libblockdev存在安全漏洞，该漏洞源于与udisks守护进程交互方式不当，可能导致本地权限提升。\n\n2. 受影响的操作系统及软件包\n·银河麒麟桌面操作系统V10 SP1\nx86_64 架构：\nlibblockdev-crypto2、libblockdev-fs2、libblockdev-loop2、libblockdev-mdraid2、libblockdev-part-err2、libblockdev-part2、libblockdev-swap2、libblockdev-utils2、libblockdev2\narm64 架构：\nlibblockdev-crypto2、libblockdev-fs2、libblockdev-loop2、libblockdev-mdraid2、libblockdev-part-err2、libblockdev-part2、libblockdev-swap2、libblockdev-utils2、libblockdev2\nsw64 架构：\nlibblockdev-crypto2、libblockdev-fs2、libblockdev-loop2、libblockdev-mdraid2、libblockdev-part-err2、libblockdev-part2、libblockdev-swap2、libblockdev-utils2、libblockdev2\nloongarch64 架构：\nlibblockdev-crypto2、libblockdev-fs2、libblockdev-loop2、libblockdev-mdraid2、libblockdev-part-err2、libblockdev-part2、libblockdev-swap2、libblockdev-utils2、libblockdev2\nmips64el架构：\nlibblockdev-crypto2、libblockdev-fs2、libblockdev-loop2、libblockdev-mdraid2、libblockdev-part-err2、libblockdev-part2、libblockdev-swap2、libblockdev-utils2、libblockdev2\n\n3. 软件包修复版本\n·银河麒麟桌面操作系统V10 SP1\n2.23-2kylin3+esm1\n\n4. 修复方法\n方法一：下载软件包进行升级安装\n通过附件软件包地址下载软件包，使用软件包升级命令根据受影响的软件包列表升级相关的组件包。\n$sudo apt-get install /Path1/Package1 /Path2/Package2 /Path3/Package3……\n注：Path 指软件包下载到本地的路径，Package指下载的软件包名称，多个软件包则以空格分开。\n\n5. 软件包下载地址\n软件包下载链接：\nhttps://security-oss.kylinos.cn/Desktop/KYSA-202506-0002/libblockdev_2.23-2kylin3%2Besm1.zip\n注：软件包仅适用于银河麒麟桌面操作系统V10 SP1版本。\n\n6. 修复验证\n使用软件包查询命令，查看相关的软件包版本大于或等于修复版本则成功修复。\n$sudo dpkg -l |grep Package\n注：Package为软件包包名。",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseKYSAReport(tt.args.report); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseKYSAReport() = %#v, want %#v", *got, *tt.want)
			}
		})
	}
}

func TestParsePage(t *testing.T) {
	type args struct {
		pageIndex int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "page 367",
			args: args{
				pageIndex: 367,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePage(tt.args.pageIndex); len(got) == 0 {
				t.Errorf("ParsePage() = %v", got)
			} else {
				for i := range got {
					if ParseKYSAReport(&got[i]) == nil {
						t.Errorf("ParseKYSAReport failed")
					}
				}
			}
		})
	}
}
