PolySwarm Search results for {{hash}}:

{{ assertions.malicious | length }} of {{ assertions | length }} reporting malicious

{% if assertions.malicious %}
Reporting Malicious: {% for assertion in assertions.malicious %}{{ assertion.engine }}{% if not loop.last %}, {% endif %}{% endfor %}
{% endif %} 

{% if assertions.non_malicious %}
Reporting non-malicious: {% for assertion in assertions.non_malicious %}{{ assertion.engine }}{% if not loop.last %}, {% endif %}{% endfor %}
{% endif %}

More info at: {{ defang_permalink }} 