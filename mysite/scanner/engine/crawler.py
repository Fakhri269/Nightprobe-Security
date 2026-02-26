import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl(url):

    links = []

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            links.append(link)

    except:
        pass

    return list(set(links))