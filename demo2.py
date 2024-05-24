def gpt_query(self, message_text, max_tokens):
    wait_time = 10
    attempt = 0
    output = ""
    while attempt < self.max_attempts:
        try:
            completion = openai.ChatCompletion.create(
                engine="csl-malicious",
                # engine="csl-malicious-35",
                # model="gpt-4-turbo-preview",
                messages=message_text,
                temperature=0.3,
                max_tokens=max_tokens,
                top_p=0.3,
                frequency_penalty=0,
                presence_penalty=0,
                stop=None
            )
            output = completion.choices[0].message['content']
            break  # 如果成功，跳出循环
        except Exception as e:
            print(f"Attempt {attempt + 1}: An error occurred: {e}")
            attempt += 1
            time.sleep(wait_time)
            wait_time += 5  # 每次失败后增加等待时间
    print(output)
    return output