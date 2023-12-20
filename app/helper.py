def create_markdown_report(sbom_data, gpt_gen = ""):
    try:
        markdown_report = ""
        # markdown_report = "\n```\n"

        if 'name' in sbom_data:
            markdown_report += f'\n# Name: {sbom_data["name"]}  \n'

        if 'format' in sbom_data:
            markdown_report += f'\n> Format: {sbom_data["format"]}  \n'

        if 'author' in sbom_data:
            markdown_report += f'\n> Author: {sbom_data["author"]}  \n'

        
        markdown_report += f'\n{gpt_gen}  \n'
        # markdown_report = "\n```\n"
        if 'components' in sbom_data:
            components = sbom_data['components']
            dep_c = 0
            for i in components:
                dep_c+= len(i['dependencies'])
                print(len(i))
            markdown_report += f'\n### Total Dependencies: {dep_c}  \n'
            
            markdown_report += f'\n## Components  \n'
            markdown_report += f'\n---  \n'
            for application in components:
                if 'type' in application and 'version' in application and 'dependencies' in application:
                    markdown_report += f'\n---  \n'
                    markdown_report += f"\n### {application['name'].capitalize()} {application['type']} (Version: {application['version']})\n"
                    markdown_report += f"- **Dependencies:**  \n"

                    for dependency in application['dependencies']:
                        if 'type' in dependency and 'name' in dependency and 'version' in dependency:
                            markdown_report += f"  - {dependency['type'].capitalize()}: **{dependency['name']} (v{dependency['version']})**:  \n"

                            if 'vulnerabilities' in dependency and dependency['vulnerabilities']:
                                for vulnerability in dependency['vulnerabilities']:
                                    if 'name' in vulnerability and 'severity' in vulnerability:
                                        markdown_report += f"      - Vulnerability: **{vulnerability['name']}**  \n"
                                        markdown_report += f"      - Severity: **{vulnerability['severity']}**  \n"
                                    else:
                                        pass
                                        # print("Incomplete vulnerability data.")
                            else:
                                pass
                                # print("No vulnerabilities found for the dependency.")
                        else:
                            pass
                            # print("Incomplete dependency data.")
                else:
                    pass
                    # print("Incomplete application data.")

        return markdown_report
    except Exception as e:
        print(f"An error occurred while creating the markdown report: {e}")
        return ""

def get_pdf(markdown_content = "# Heading 1"):
    import requests

    url = "https://md-to-pdf.fly.dev"

    params = {
        "css": "",
        "engine": "weasyprint"  # Optional PDF conversion engine (weasyprint, wkhtmltopdf, pdflatex)
    }

    response = requests.post(url, data={"markdown": markdown_content}, params=params)

    if response.status_code == 200:
        return response.content
    else:
        print(f"Error: {response.status_code}\n{response.text}")

from flask_mail import Message
from .config import mail
def send_email(email,liberary, version,link,lib_message):
    # try:
        subject = "new version of liberaries found in you SBOM"
        message = Message(subject=subject, recipients=[email])
        message.body ='''
I hope this message finds you well. We are herby notifying you for the release of a new version of the '''+liberary+''' library, packed new features and enhancements that will elevate your user experience.\n\n

Description of the New Version:\n\n
'''+lib_message+'''
\n\n
To delve deeper into the enhancements and explore the full potential of the latest version, we encourage you to log in to your dashboard. The link to access your dashboard is provided below:
\n\n
'''+link+'''
\n\n
We believe that these updates will significantly enhance your experience with the x library, and we look forward to hearing your feedback.
\n\n
Thank you for your continued support.
\n\n
Best regards,
\n\n
Team secure compose
'''
        mail.send(message)
        return True
    # except Exception as e:
    #     print("Error sending email:", str(e))
    #     return False


import os
import openai


def preset_gpt(System_prompt,prompt):
    # try:
    openai.api_key = os.getenv("OPEN_AI_KEY")
    response = openai.ChatCompletion.create(
        model="gpt-4-1106-preview",
        messages=[
            {
            "role": "system",
            "content": System_prompt
            },
            {
            "role": "user",
            "content": prompt
            }
        ],
        temperature=1,
        max_tokens=1195,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    
    # print("Response:", response)
    # print("First choice:", response.choices[0] if response.choices else "No choices")
    
    return response.choices[0].message['content'].strip() if response.choices else None
    # except Exception as e:
    #     print(e)
    #     from app.utils.Others import write_error
    #     write_error('preset_gpt'+str(e)+"\n\nSystem_prompt"+System_prompt+"\n\nprompt"+prompt)
    #     return None
    
# print(preset_gpt("add the two number", "1, 32"))