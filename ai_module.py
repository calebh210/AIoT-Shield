from openai import OpenAI
import os
import json

def set_api_key():
	os.environ["OPENAI_API_KEY"] = input("Enter your OpenAI API key: \n")

# https://platform.openai.com/docs/guides/text-generation
def get_parameters(req):
	client = OpenAI()
	response = client.chat.completions.create(
	model="gpt-3.5-turbo",
	messages=[
		{"role": "system", "content": "You are a helpful assistant."},
		{"role": "user", "content": f"This is a request from a webpage I am trying to log in to: {req}"},
		{"role": "user", "content": f"Respond in this format: VENDOR=[vendor],USERNAME=[username_paramter],PASSWORD=[password_parameter]"},
		{"role": "user", "content": "Who is the vendor of this webpage? (Examples: Hewlett-Packard, Dell, etc.) What are the post parameters required to respond to this request in order to login?"}
	]
	)

	result = parse_ai_output(response.choices[0].message.content)
	print(result)


#function to parse the AI Output. It needs error handling incase the AI freaks out
def parse_ai_output(resp):
	parsed_output = []
	r = resp.split(",")
	for i in r:
		param = i.split("=")[1]
		parsed_output.append(param)
	return parsed_output

