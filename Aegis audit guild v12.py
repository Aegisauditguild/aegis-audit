import os

HTML_TEMPLATE = "This is a template with monthly waste: {}, annual waste: {}, audit fee: {}, home equivalency: {}" 

def generate_report(monthly_waste, annual_waste, audit_fee, home_equivalency):
    report_content = HTML_TEMPLATE.format(monthly_waste, annual_waste, audit_fee, home_equivalency)
    report_path = os.path.join(os.getcwd(), 'aegis_audit_report.html')
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        print(f"[SUCCESS] Report saved to: {os.path.abspath(report_path)}")
        return report_path
    except Exception as e:
        print(f"[ERROR] Failed to write report: {e}")
        return None

if __name__ == "__main__":
    generate_report("£842.00", "£10,104.00", "£250.00", "16 homes")