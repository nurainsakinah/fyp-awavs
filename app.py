from flask import Flask, render_template, request, redirect, url_for
import matplotlib
import scanner
import sqli_scanner
import csrf_scanner
import xss_scanner
from colorama import init
from flask_sqlalchemy import SQLAlchemy
from flask import json
matplotlib.use('Agg')  # Use Agg backend to avoid Tkinter-related issues
import matplotlib.pyplot as plt
import os

init(autoreset=True)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///status_url.db'
db = SQLAlchemy(app)

# Assuming your SQLite database file is named 'database.db'
DATABASE_URL = "sqlite:///" + os.path.join(os.getcwd(), "status_url.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL

class blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255))
    category = db.Column(db.String(255))
    link = db.Column(db.String(255))
    xss_result = db.Column(db.Boolean)  
    csrf_result = db.Column(db.Boolean)
    sqli_result = db.Column(db.Boolean)
    total_xss_count=db.Column(db.Integer)
    total_csrf_count=db.Column(db.Integer)
    total_sqli_count=db.Column(db.Integer)
    
class whitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255))
    category = db.Column(db.String(255))
    summary = db.Column(db.Text)

def add_to_blacklist(url, category, link, xss_result, csrf_result, sqli_result, total_xss_count, total_csrf_count, total_sqli_count):
    blacklist_entry = blacklist(
        url=url,
        category=category,
        link=link,
        xss_result=xss_result,
        csrf_result=csrf_result,
        sqli_result=sqli_result,
        total_xss_count=total_xss_count,
        total_csrf_count=total_csrf_count,
        total_sqli_count=total_sqli_count,
    )
    db.session.add(blacklist_entry)
    db.session.commit()

def add_to_whitelist(url, category, summary):
    summary_str = json.dumps(list(summary))
    whitelist_entry = whitelist(
        url=url,
        category=category,
        summary=summary_str,
    )
    db.session.add(whitelist_entry)
    db.session.commit()

def is_in_blacklist(url, category):
    query_result = blacklist.query.filter_by(url=url, category=category).first()
    if query_result:
        return True
    else:
        return False

def is_in_whitelist(url, category):
    query_result = whitelist.query.filter_by(url=url, category=category).first()
    if query_result:
        return True
    else:
        return False

def get_totals():
    total_xss = blacklist.query.with_entities(db.func.sum(blacklist.total_xss_count)).scalar() or 0
    total_csrf = blacklist.query.with_entities(db.func.sum(blacklist.total_csrf_count)).scalar() or 0
    total_sqli = blacklist.query.with_entities(db.func.sum(blacklist.total_sqli_count)).scalar() or 0

    total_all = total_xss + total_csrf + total_sqli

    return total_xss, total_csrf, total_sqli, total_all

def get_category_distribution():
    categories = db.session.query(blacklist.category, db.func.count().label('count')).group_by(blacklist.category).all()
    category_distribution = {category: count for category, count in categories}
    return category_distribution


import io
import base64
import threading
from queue import Queue

def create_vulnerability_pie_chart(total_xss, total_csrf, total_sqli, pie_result_queue):
    labels = ['XSS', 'CSRF', 'SQLi']
    counts = [total_xss, total_csrf, total_sqli]
    colors = ['#a67d93', '#e79b93', '#ffe7b1']  # Customize the colors here

    plt.figure(figsize=(5, 5))
    plt.pie(counts, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('Vulnerability Distribution')

    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png')
    image_stream.seek(0)

    base64_image = base64.b64encode(image_stream.read()).decode('utf-8')
    plt.close()

    pie_result_queue.put(base64_image)

def create_category_bar_chart(category_distribution, bar_result_queue):
    categories = list(category_distribution.keys())
    counts = list(category_distribution.values())
    colors = ['#b5b0aa', '#73bbdb', '#9c5465', '#355e73']

    # Create a pie chart
    plt.figure(figsize=(5, 5))
    plt.pie(counts, labels=categories, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('Category Distribution')

    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png')
    image_stream.seek(0)

    base64_image = base64.b64encode(image_stream.read()).decode('utf-8')
    plt.close()

    bar_result_queue.put(base64_image)

@app.route('/')
def index():
    # Assume you have functions get_totals(), get_category_distribution(), and others defined

    total_xss, total_csrf, total_sqli, total_all = get_totals()
    category_distribution = get_category_distribution()

    vulnerability_result_queue = Queue()
    vulnerability_chart_thread = threading.Thread(target=create_vulnerability_pie_chart, args=(total_xss, total_csrf, total_sqli, vulnerability_result_queue))
    vulnerability_chart_thread.start()
    vulnerability_chart_thread.join()
    vulnerability_chart_data = vulnerability_result_queue.get()
   
    category_result_queue = Queue()
    category_chart_thread = threading.Thread(target=create_category_bar_chart, args=(category_distribution, category_result_queue))
    category_chart_thread.start()
    category_chart_thread.join()
    category_chart_data = category_result_queue.get()

    top_blacklist_entries = blacklist.query.order_by(blacklist.id.desc()).limit(3).all()
    top_whitelist_entries = whitelist.query.order_by(whitelist.id.desc()).limit(3).all()

    return render_template('index.html', total_xss=total_xss, total_csrf=total_csrf, total_sqli=total_sqli, total_all=total_all, 
                           vulnerability_chart_data=vulnerability_chart_data, category_chart_data=category_chart_data,
                           top_blacklist_entries=top_blacklist_entries, top_whitelist_entries=top_whitelist_entries)


@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['url'].strip()
    if not target_url.endswith('/'):
        target_url += '/'
    category = request.form['category'].strip()
    

    scan = scanner.Scanner(target_url)

    scan.crawl()

    scan_xss = xss_scanner.xss_scanner(scan.session)
    scan_csrf = csrf_scanner.csrf_scanner(scan.session)
    scan_sqli = sqli_scanner.sqli_scanner(scan.session)

    results = []

    total_xss_count = 0
    total_csrf_count = 0
    total_sqli_count = 0

    for link in scan.target_links:
        result = {}
        result['link'] = link
        result['xss_result'] = scan_xss.run_xss_test(link)
        result['csrf_result'] = scan_csrf.run_csrf_test(link)
        result['sqli_result'] = scan_sqli.run_sqli_test(link)

        total_xss_count += result['xss_result']
        total_csrf_count += result['csrf_result']
        total_sqli_count += result['sqli_result']

        results.append(result)

        total_xss_count = max(total_xss_count, 0)
        total_csrf_count = max(total_csrf_count, 0)
        total_sqli_count = max(total_sqli_count, 0) 
    
    message = ""
    if  total_xss_count == 0 and total_csrf_count == 0 and total_sqli_count == 0:
        summary = {'status': 'Whitelisted',
                   'count_xss': total_xss_count,
                   'count_csrf': total_csrf_count,
                   'count_sqli': total_sqli_count}
        if not is_in_whitelist(target_url, category):
            add_to_whitelist(url=target_url, category=category, summary=summary)
        else:
            message = (f"The URL {target_url} is already in the whitelist.")
        
    
    else:
        summary = {'status': 'Blacklisted',
                   'count_xss': total_xss_count,
                   'count_csrf': total_csrf_count,
                   'count_sqli': total_sqli_count}
        if not is_in_blacklist(target_url, category):
            add_to_blacklist(
                url=target_url,
                category=category,
                link=link,
                xss_result=bool(result['xss_result']),
                csrf_result=bool(result['csrf_result']),
                sqli_result=bool(result['sqli_result']),
                total_xss_count=total_xss_count,
                total_csrf_count=total_csrf_count,
                total_sqli_count=total_sqli_count
            )
        else:
            message = (f"The URL {target_url} is already in the blacklist.")
    
    return render_template('result.html', url=target_url, category=category, results=results, summary=summary, message=message)

@app.route('/csrf')
def csrf():
    # Your CSRF view logic goes here
    return render_template('csrf.html')

@app.route('/xss')
def xss():
    # Your XSS view logic goes here
    return render_template('xss.html')

@app.route('/sqli')
def sqli():
    # Your SQLi view logic goes here
    return render_template('sqli.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=False)
