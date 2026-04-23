from flask import Flask, render_template_string
import json



app = Flask(__name__)

HTML = """
<h1>Docker Security Report</h1>

{% for c in data["containers"] %}
<hr>
<h3>{{ c["id"] }}</h3>
<p>Image: {{ c["image"] }}</p>
<p>Risk: {{ c["risk"] }}</p>
<ul>
{% for i in c["issues"] %}
<li>{{ i }}</li>
{% endfor %}
</ul>
{% endfor %}
"""

@app.route("/")
def index():
    with open("report.json") as f:
        data = json.load(f)

    return render_template_string(HTML, data=data)

if __name__ == "__main__":
    app.run(debug=True)