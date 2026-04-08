import os

def generate_report(monthly_waste, annual_waste, audit_fee, home_equivalency):
    html_template = """
    <html>
        <head>
            <title>Aegis Audit Report</title>
        </head>
        <body>
            <h1>Aegis Audit Report</h1>
            <p>Monthly Waste: {monthly_waste}</p>
            <p>Annual Waste: {annual_waste}</p>
            <p>Audit Fee: {audit_fee}</p>
            <p>Home Equivalency: {home_equivalency}</p>
        </body>
    </html>
    """
    report_content = html_template.format(
        monthly_waste=monthly_waste,
        annual_waste=annual_waste,
        audit_fee=audit_fee,
        home_equivalency=home_equivalency
    )
    report_path = os.path.join(os.getcwd(), 'audit_report.html')
    with open(report_path, 'w') as report_file:
        report_file.write(report_content)
    print(f'Report generated at: {report_path}')

# Example usage: generate_report(1000, 12000, 300, '10 homes')