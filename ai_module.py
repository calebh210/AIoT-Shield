from openai import OpenAI
from sql_module import read_table_by_key
import os
import json

def set_api_key(file):
	if file:
		f = open("API_KEY")
		os.environ["OPENAI_API_KEY"] = f.read()
	else:
		os.environ["OPENAI_API_KEY"] = input("Enter your OpenAI API key: \n")

# https://platform.openai.com/docs/guides/text-generation
# this returns in the format of vendor, username, password
def get_parameters(req):
	set_api_key(True)
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
	print(response.choices[0].message.content)
	result = parse_ai_output(response.choices[0].message.content)
	print(result)
	return result

#function to parse the AI Output. It needs error handling incase the AI freaks out
def parse_ai_output(resp):
	parsed_output = []
	r = resp.split(",")
	for i in r:
		param = i.split("=")[1]
		parsed_output.append(param)
	return parsed_output

#function to generate report based off of data in vulns table
def generate_report(data):
	set_api_key(True)
	client = OpenAI()
	response = client.chat.completions.create(
	model="gpt-4-turbo-preview",
	messages=[
		{"role": "system", "content": "You are an assistant used to generate reports detailed the findings from Penetration Tests."},
		{"role": "user", "content": f"This is a table which contains the found vulnerabilities from the test: {data}"},
		#{"role": "user", "content": f"Respond in this format: VENDOR=[vendor],USERNAME=[username_paramter],PASSWORD=[password_parameter]"},
		{"role": "user", "content": "Create a report using the given data. Detail the hostname, what the vulnerability is, how severe it is, and how it can be fixed. "}
	]
	)
	print(response.choices[0].message.content)

# BELOW IS TEST FUNCTIONS - REMOVE LATER
# data = read_table_by_key("vulns","host","192.168.56.110")
# generate_report(data)