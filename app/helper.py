
def create_markdown_report(sbom_data):
    markdown_report = ""

    try:
        for application in sbom_data:
            if 'type' in application and 'version' in application and 'dependencies' in application:
                markdown_report += f"\n## {application['type'].capitalize()} Application (Version: {application['version']})\n"
                markdown_report += f"- **Dependencies:**\n"

                for dependency in application['dependencies']:
                    if 'type' in dependency and 'name' in dependency and 'version' in dependency:
                        markdown_report += f"  {dependency['type'].capitalize()}: **{dependency['name']} (v{dependency['version']})**:  \n"
                        
                        if 'vulnerabilities' in dependency and dependency['vulnerabilities']:
                            for vulnerability in dependency['vulnerabilities']:
                                if 'name' in vulnerability and 'severity' in vulnerability:
                                    markdown_report += f"      - **{vulnerability['name']}**  \n"
                                    markdown_report += f"           - **Severity:** {vulnerability['severity']}  \n"
                                    # markdown_report += f"          - **Vulnerability:** [{vulnerability['title']}]({vulnerability['url']})  \n"
                                    # markdown_report += f"              - **CVSS Score:** {vulnerability['cvss']['score']}  \n"
                                    # markdown_report += f"              - **Range:** {vulnerability['range']}  \n"
                                else:
                                    print("Incomplete vulnerability data.")
                        else:
                            print("No vulnerabilities found for the dependency.")
                    else:
                        print("Incomplete dependency data.")
            else:
                print("Incomplete application data.")

        return markdown_report
    except Exception as e:
        print(f"An error occurred while creating the markdown report: {e}")
        return ""


# Example usage
sbom_data = [...]  # Your SBOM data here
markdown_report = create_markdown_report(sbom_data)
print(markdown_report)


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