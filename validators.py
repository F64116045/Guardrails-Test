import os
import logging
from guardrails import Guard
from guardrails.hub import DetectPII, ValidLength, BanList

import logging
# 如果要Call GPT
# os.environ["OPENAI_API_KEY"] = ""
logging.getLogger("opentelemetry.sdk.trace.export").setLevel(logging.WARNING)

# -------------------------------
# Input Guard 
# -------------------------------
# 要封鎖的關鍵字
banned_keywords = [
    "SELECT", "FROM", "WHERE",   # SQL injection
    "DROP", "DELETE", "INSERT",  #
    "script", "iframe",          # HTML injection
    "console", "eval", "fetch"   # JavaScript injection
]

input_guard = Guard(name="input_guard").use(
    # 限制輸入長度介於 5~1000 字元，否則丟出例外
    ValidLength(min=5, max=1000, on_fail="exception")
).use(
    # 偵測 PII（Ex : 電話與信用卡），如果發現則會自動以 fix 方式處理
    DetectPII(["PHONE_NUMBER", "CREDIT_CARD"], on_fail="fix")
).use(
    # 禁止包含 SQL 語法相關的關鍵詞，若出現則直接丟出例外
    BanList(banned_words=banned_keywords, on_fail="exception")
)

# -------------------------------
# Input 涵蓋下列情況：
# 1. Valid Input：乾淨合法的輸入，不包含任何敏感詞或特殊結構。
# 2. Too Short：輸入長度小於最小限制（不足 5 個字元）。
# 3. Too Long：輸入長度超過最大限制（超過 1000 個字元）。
# 4. Contains PII (fix)：輸入中包含信用卡號與電話號碼。
# 5. Contains PII (fix)2：輸入中包含電子郵件與電話號碼。
# 6. Contains SQL Keywords：輸入中包含 SQL 語法關鍵字，例如 SELECT、FROM、WHERE。
# 7. Contains SQL Keywords2：輸入中包含經過混淆處理的 SQL 關鍵字（加入干擾）。
# 8. Contains DROP：輸入中包含 SQL 指令 DROP。
# 9. Contains DELETE：輸入中包含 SQL 指令 DELETE。
# 10. Contains INSERT：輸入中包含 SQL 指令 INSERT。
# 11. Contains script：輸入中包含 HTML 的 <script> 標籤。
# 12. Contains iframe：輸入中包含 HTML 的 <iframe> 標籤。
# 13. Contains console：輸入中包含 JavaScript 的 console 。
# 14. Contains eval：輸入中包含 eval 函式。
# 15. Contains fetch：輸入中包含 fetch API。
# -------------------------------
input_tests = {
    "Valid Input": "This is a perfectly clean input message.",
    "Too Short": "ABC",
    "Too Long": "x" * 1100,
    "Contains PII (fix)": "My credit card is 4111 1111 1111 1111, and my phone is 0912-345-678.",
    "Contains PII (fix)2": "My email is test@gmail.com, and my phone is 0912-345-678.",#不會擋Email
    "Contains SQL Keywords": "SELECT * FROM users WHERE password = '1234';",
    "Contains SQL Keywords2": "SE L E!C \T * FR & OM us e rs WH \ ER * E pas sword = '1234';",#增加干擾
    "Contains DROP": "DROP TABLE users will remove the table.",
    "Contains DELETE": "DELETE FROM users where id=1;",
    "Contains INSERT": "INSERT INTO users VALUES ('admin');",
    "Contains script": "<script>alert('XSS');</script>",
    "Contains iframe": "<iframe src='http://malicious.com'></iframe>",
    "Contains console": "console.log('debug message');",
    "Contains eval": "eval('dangerous code')",
    "Contains fetch": "fetch('http://example.com/api')"
}

print("=== Input Guard 測試 ===")
for label, content in input_tests.items():
    print(f"\n[{label}]")
    try:
        validated = input_guard.validate(content)
        print("驗證通過")
        print("修正後結果:", validated)
    except Exception as e:
        print("驗證失敗:", e)

# -------------------------------
# Output Guard
# -------------------------------
output_guard = Guard(name="output_guard").use(
    ValidLength(min=5, max=1000, on_fail="exception")
).use(
    DetectPII(["PHONE_NUMBER", "CREDIT_CARD"], on_fail="fix")
).use(
    BanList(banned_words=banned_keywords, on_fail="exception")
)


# -------------------------------
# Call GPT 模型
# -------------------------------
#result = output_guard(
#    messages=[{"role":"user", "content":input_guard["Valid Input"]}],
#    model="gpt-4.1-nano",
#)


# 模擬輸出 
output_tests = {
    "Valid Output": "Your order has been processed successfully.",
    "Output with PII (fix)": "Please contact me at 0912-345-678 for further assistance.",
    "Output with SQL Keywords": "Here's a sample: SELECT * FROM table_name;"
}

print("\n=== Output Guard 測試 ===")
for label, message in output_tests.items():
    print(f"\n[{label}]")
    try:
        validated_output = output_guard.validate(message)
        print("驗證通過")
        print("修正後結果:", validated_output)
    except Exception as e:
        print("驗證失敗:", e)
