# Guardrails輸入與輸出驗證

使用 [Guardrails AI](https://github.com/shreyashankar/gpt-guardrails) 來驗證 LLM 的輸入與輸出，包含以下功能:
- 輸入問題長度避免過長或過短
- 輸入內容不包含個資
- 防止輸入中包含 HTML tag、SQL、程式碼
- 輸出問題長度避免過長或過短
- 限制輸出不可包含敏感個資
- 防止生成的回答中包含 HTML tag、SQL、程式碼
---
### 套件

```bash
pip install guardrails-ai
```

### Guardrails Hub 元件
```bash
guardrails hub install hub://guardrails/ban_list
guardrails hub install hub://guardrails/detect_pii
guardrails hub install hub://guardrails/valid_length
```

---

## 測試範例

### 輸入涵蓋以下情境：

1. 合法輸入（乾淨且無問題）
2. 長度太短（少於 5 字元）
3. 長度太長（超過 1000 字元）
4. 包含信用卡與電話號碼（PII）
5. 包含 email 與電話號碼
6. 含 SQL 關鍵字：`SELECT`, `FROM`, `WHERE`, `DROP`, `DELETE`, `INSERT`
7. 混淆過的 SQL 關鍵字（含空格與符號干擾）
8. 含 HTML tag：`<script>`, `<iframe>`
9. 含 JavaScript 語法：`console`, `eval`, `fetch`

### 模擬輸出測試：

- 正常的 GPT 輸出文字
- 含有電話號碼的回應（PII）
- 含 SQL 語法片段的輸出

---

## DetectPII 支援的 Entity Types
- `CREDIT_CARD`：信用卡號碼  
- `CRYPTO`：加密貨幣錢包（目前支援 Bitcoin）  
- `DATE_TIME`：日期、時間或時間區間  
- `EMAIL_ADDRESS`：電子郵件地址  
- `IBAN_CODE`：國際銀行帳號碼  
- `IP_ADDRESS`：IP 位址  
- `NRP`：國籍、宗教或政治團體  
- `LOCATION`：地理/政治區域名稱  
- `PERSON`：人名  
- `PHONE_NUMBER`：電話號碼  
- `MEDICAL_LICENSE`：醫療執照編號  
- `URL`：網址  

這邊預設使用：
```python
DetectPII(["PHONE_NUMBER", "CREDIT_CARD"], on_fail="fix")
```
可以依需求擴充更多欄位，例如 `EMAIL_ADDRESS`、`PERSON`、`URL` 等。

##  結果 (部分)
實際執行 `input_output_guard.py` 的部分輸出結果：

```
[Valid Input]
驗證通過
修正後結果: This is a perfectly clean input message.

[Too Short]
驗證失敗: Value has length less than 5.

[Too Long]
驗證失敗: Value has length greater than 1000.

[Contains PII (fix)]
驗證通過
修正後結果: My credit card is <CREDIT_CARD>, and my phone is <PHONE_NUMBER>.

[Contains PII (fix)2]
驗證通過
修正後結果: My email is test@gmail.com, and my phone is <PHONE_NUMBER>.

[Contains SQL Keywords]
驗證失敗: Output contains banned words

[Contains SQL Keywords2]
驗證失敗: Output contains banned words
```
...
