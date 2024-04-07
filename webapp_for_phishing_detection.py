import numpy as np
from joblib import load
import requests
from bs4 import BeautifulSoup
from sklearn.preprocessing import MinMaxScaler
import streamlit as st
import tldextract
from urllib.parse import urlparse

# Load the trained model and scaler
final_model, scaler = load("C:/Users/DELL/Downloads/phishing_trained_model.joblib")

# has_input
def has_input(soup):
    if len(soup.find_all("input")):
        return 1
    else:
        return 0


# has_button
def has_button(soup):
    if len(soup.find_all("button")) > 0:
        return 1
    else:
        return 0


# has_image
def has_image(soup):
    if len(soup.find_all("image")) == 0:
        return 0
    else:
        return 1


# has_submit
def has_submit(soup):
    for button in soup.find_all("input"):
        if button.get("type") == "submit":
            return 1
        else:
            pass
    return 0


# has_link
def has_link(soup):
    if len(soup.find_all("link")) > 0:
        return 1
    else:
        return 0


# has_password
def has_password(soup):
    for input in soup.find_all("input"):
        if (input.get("type") or input.get("name") or input.get("id")) == "password":
            return 1
        else:
            pass
    return 0


# has_email_input
def has_email_input(soup):
    for input in soup.find_all("input"):
        if (input.get("type") or input.get("id") or input.get("name")) == "email":
            return 1
        else:
            pass
    return 0


# has_hidden_element
def has_hidden_element(soup):
    for input in soup.find_all("input"):
        if input.get("type") == "hidden":
            return 1
        else:
            pass
    return 0


# has_audio
def has_audio(soup):
    if len(soup.find_all("audio")) > 0:
        return 1
    else:
        return 0


# has_video
def has_video(soup):
    if len(soup.find_all("video")) > 0:
        return 1
    else:
        return 0


# number_of_inputs
def number_of_inputs(soup):
    return len(soup.find_all("input"))


# number_of_buttons
def number_of_buttons(soup):
    return len(soup.find_all("button"))


# number_of_images
def number_of_images(soup):
    image_tags = len(soup.find_all("image"))
    count = 0
    for meta in soup.find_all("meta"):
        if meta.get("type") or meta.get("name") == "image":
            count += 1
    return image_tags + count


# number_of_option
def number_of_option(soup):
    return len(soup.find_all("option"))


# number_of_list
def number_of_list(soup):
    return len(soup.find_all("li"))


# number_of_TH
def number_of_TH(soup):
    return len(soup.find_all("th"))


# number_of_TR
def number_of_TR(soup):
    return len(soup.find_all("tr"))


# number_of_href
def number_of_href(soup):
    count = 0
    for link in soup.find_all("link"):
        if link.get("href"):
            count += 1
    return count


# number_of_paragraph
def number_of_paragraph(soup):
    return len(soup.find_all("p"))


# number_of_script
def number_of_script(soup):
    return len(soup.find_all("script"))


# length_of_title
def length_of_title(soup):
    if soup.title == None:
        return 0
    return len(soup.title.text)

# has h1
def has_h1(soup):
    if len(soup.find_all("h1")) > 0:
        return 1
    else:
        return 0


# has h2
def has_h2(soup):
    if len(soup.find_all("h2")) > 0:
        return 1
    else:
        return 0


# has h3
def has_h3(soup):
    if len(soup.find_all("h3")) > 0:
        return 1
    else:
        return 0


# length of text
def length_of_text(soup):
    return len(soup.get_text())


# number of clickable button
def number_of_clickable_button(soup):
    count = 0
    for button in soup.find_all("button"):
        if button.get("type") == "button":
            count += 1
    return count


# number of a
def number_of_a(soup):
    return len(soup.find_all("a"))


# number of img
def number_of_img(soup):
    return len(soup.find_all("img"))


# number of div class
def number_of_div(soup):
    return len(soup.find_all("div"))


# number of figures
def number_of_figure(soup):
    return len(soup.find_all("figure"))


# has footer
def has_footer(soup):
    if len(soup.find_all("footer")) > 0:
        return 1
    else:
        return 0


# has form
def has_form(soup):
    if len(soup.find_all("form")) > 0:
        return 1
    else:
        return 0


# has textarea
def has_text_area(soup):
    if len(soup.find_all("textarea")) > 0:
        return 1
    else:
        return 0


# has iframe
def has_iframe(soup):
    if len(soup.find_all("iframe")) > 0:
        return 1
    else:
        return 0


# has text input
def has_text_input(soup):
    for input in soup.find_all("input"):
        if input.get("type") == "text":
            return 1
    return 0


# number of meta
def number_of_meta(soup):
    return len(soup.find_all("meta"))


# has nav
def has_nav(soup):
    if len(soup.find_all("nav")) > 0:
        return 1
    else:
        return 0


# has object
def has_object(soup):
    if len(soup.find_all("object")) > 0:
        return 1
    else:
        return 0


# has picture
def has_picture(soup):
    if len(soup.find_all("picture")) > 0:
        return 1
    else:
        return 0


# number of sources
def number_of_sources(soup):
    return len(soup.find_all("source"))


# number of span
def number_of_span(soup):
    return len(soup.find_all("span"))


# number of table
def number_of_table(soup):
    return len(soup.find_all("table"))
def url_length_greater_than_54(url):
    if len(url) >= 54:
        return 1
    else:
        return 0

def has_hyphens(url):
    if '-' in urlparse(url).netloc: 
        return 1
    else:
        return 0


def count_subdomains(url):
    
    ext = tldextract.extract(url)
    subdomains = ext.subdomain.split('.')  
    # Return the count of subdomains
    return len(subdomains)

def mark_phishing_tld(url):
    ext = tldextract.extract(url)
    phishing_tlds = ['xyz', 'top', 'info', 'loan', 'xmr', 'ink', 'sk', 'ag', 'ryukyu', 'ltc', 'gr', 'fund', 'sx']

    # Convert both TLD and phishing_tlds list to lowercase for case-insensitive comparison
    tld = ext.suffix.lower()
    phishing_tlds = [tld.lower() for tld in phishing_tlds]

    if tld in phishing_tlds:
        return 1  # Mark as phishing
    else:
        return 0  # Mark as legitimate
    
    
# Define the features to be scaled
columns_to_scale = ['number_of_clickable_button', 'number_of_a', 'number_of_img', 'number_of_div',
                    'number_of_figure', 'number_of_table', 'number_of_inputs', 'number_of_buttons',
                    'number_of_images', 'number_of_option', 'number_of_list', 'number_of_TH',
                    'number_of_TR', 'number_of_href', 'number_of_paragraph', 'number_of_script',
                    'number_of_span', 'number_of_sources', 'length_of_text', 'number_of_meta',
                    'subdomain_count', 'length_of_title']

def extract_features_from_url(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print("HTTP connection was not successful for the URL:", url)
            return None
        soup = BeautifulSoup(response.content, "html.parser")
        unscaled_features = {
            'has_input': has_input(soup),
            'has_button': has_button(soup),
            'has_image': has_image(soup),
            'has_submit': has_submit(soup),
            'has_link': has_link(soup),
            'has_password': has_password(soup),
            'has_email_input': has_email_input(soup),
            'has_hidden_element': has_hidden_element(soup),
            'has_audio': has_audio(soup),
            'has_video': has_video(soup),
            'number_of_inputs': number_of_inputs(soup),
            'number_of_buttons': number_of_buttons(soup),
            'number_of_images': number_of_images(soup),
            'number_of_option': number_of_option(soup),
            'number_of_list': number_of_list(soup),
            'number_of_TH': number_of_TH(soup),
            'number_of_TR': number_of_TR(soup),
            'number_of_href': number_of_href(soup),
            'number_of_paragraph': number_of_paragraph(soup),
            'number_of_script': number_of_script(soup),
            'length_of_title': length_of_title(soup),
            'has_h1': has_h1(soup),
            'has_h2': has_h2(soup),
            'has_h3': has_h3(soup),
            'length_of_text': length_of_text(soup),
            'number_of_clickable_button': number_of_clickable_button(soup),
            'number_of_a': number_of_a(soup),
            'number_of_img': number_of_img(soup),
            'number_of_div': number_of_div(soup),
            'number_of_figure': number_of_figure(soup),
            'has_footer': has_footer(soup),
            'has_form': has_form(soup),
            'has_text_area': has_text_area(soup),
            'has_iframe': has_iframe(soup),
            'has_text_input': has_text_input(soup),
            'number_of_meta': number_of_meta(soup),
            'has_nav': has_nav(soup),
            'has_object': has_object(soup),
            'has_picture': has_picture(soup),
            'number_of_sources': number_of_sources(soup),
            'number_of_span': number_of_span(soup),
            'number_of_table': number_of_table(soup),
            'url_length_greater_than_54': url_length_greater_than_54(url),
            'has_hyphens': has_hyphens(url),
            'subdomain_count': count_subdomains(url),
            'has_Phishing_TLD': mark_phishing_tld(url)}

        return unscaled_features

    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return None

def predict_url(url):
    try:
        unscaled_features = extract_features_from_url(url)
        if unscaled_features:
            scaled_features_array = scaler.transform(np.array([[unscaled_features[feature] for feature in columns_to_scale]]))
            encoded_url_array = np.concatenate((scaled_features_array,
                                                 np.array([[unscaled_features[feature] for feature in unscaled_features
                                                            if feature not in columns_to_scale]])), axis=1)
            predicted_label = final_model.predict(encoded_url_array)
            if predicted_label == 1:
                return "Attention! This web page is a potential PHISHING!"
            else:
                return "This web page seems a legitimate!"
        else:
            return "Failed to extract features from the URL."
    except Exception as e:
        print("Error:", e)
        return "An error occurred."
    
  
# Streamlit UI

st.title("WEB PHISHING DETECTION")
st.subheader('This is a "ML-based Web-app" .Objective of the web-app is to detecting phishing websites using the HTML contents in the website and URL structures!')
st.write("This web-app predicts whether a website is phishing or legitimate. Users provide a URL as input, and based on the URL, the web-app will extract features from the website's content to determine its authenticity.")
with st.expander('EXAMPLE PHISHING URLs (These URLs and their features were not included in the dataset; they are used for testing purposes):'):
    st.caption('REMEMBER: PHISHING WEB PAGES HAVE A SHORT LIFECYCLE! Phishing URLs often have a short lifespan, and the model may not always extract features from them successfully, as they may have been blocked. Therefore, it is essential to use recently listed phishing URLs for predictions.')
    st.write('https://register-jesse.org/')
    st.write('https://claim-jesse.org')
    st.write('https://vod-ktk.com')
    st.write('https://crypto-eth-event.top')
    st.write('https://paramgaming-connects.com/connect.html')
    st.write('https://rune-punks.xyz')
    st.write('https://home-100762.weeblysite.com/')
    st.write('https://kraken-trust.com')
    st.write('https://earn.ventory-lab.com/')
    st.write('https://bytes-distribution.app')
    st.write('https://nft-ethvenice.com')
    st.write('https://wenexchange-airdrop.com')
    st.write('https://sols-spl20.web.app')
    st.write('https://nft-ethvenice.com')
    st.write('https://earn.mog-coin.org')
    st.write('https://net-customers.com')
    st.write('https://giacenza.spedizione.20-218-153-131.cprapid.com/brt/update.php?...')
    st.write('https://viewexo.native-webspace.com/')
    st.write('https://netlify-apps.pages.dev/rep/')
    st.write('https://web3-node-ct0.pages.dev/wallets/wallets...')
    st.write('https://liquids.redirmagal.com/redirecionamento/?https://bradesco.com....')
    st.write('https://new.express.adobe.com/webpage/kVjowlPUzbnCB...')
    st.write('https://att-hgfdswdf.weeblysite.com/')
    st.write('https://business-email-103802.weeblysite.com/')
    st.write('https://support.clean-mx.com/clean-mx/phishing.php')
    st.write('https://link.springer.com/10.1007/s10207-023-00768-x')
    st.write('https://link.springer.com/chapter/10.1007/978-3-030-86137-7_33')
    st.write('https://fastrack-dapps.pages.dev/rep/')
    st.write('http://seguranca-apple.com/')
    st.write('https://temp-xlhxgeeyzklzfynhkuwv.webadorsite.com/...')
    st.write('https://space-fi.org')
    st.write('https://stacke-vaiotai.com')
    st.write('https://coinmarketcap-auth-web.web.app')
    st.write('https://jumper-exchange.online')
    st.write('http://shop-ltau.site/')
    st.write('https://presale.tradex-taopad.io')
    st.write('https://pi-network.icu')
    st.write('https://satoshi-app.network')
    st.write('https://app-bancosofisa.com/lander')
    st.write('	https://shiba-claim.shop/')
    st.write('https://migrate-makerdao.pages.dev/')
    st.write('http://migrate-makerdao.pages.dev')
    st.write('https://servi-id.com')
    st.write('https://leonie-patricia.com/3458674586.php')
    st.write('https://steth-pools.com/')
    st.write('https://steth-shares.com')
    st.write('	https://testie.nitro-ncp.xyz/kops/W568H/pay/')
    st.write('https://pt-viaverde.com')
    st.write('https://secure-seacomm.weebly.com/')
    st.write('https://free-flre-spingptdcaz.mediaviralterbaru.my.id/vhsfhqpdhdsih6')
    st.write('_https://supercard-login.eu/_')
    st.write('_https://google-newsletters.blogspot.com/_')
    st.write('https://google-newsletters.blogspot.ch/ ')
    st.write('https://page-violation-review.replit.app/')
    st.write('https://metamask-wyllet.webflow.io/')
    
    

url_to_test = st.text_input("Enter the  URL")

if st.button("Check URL"):
    if not url_to_test:
        st.write("Please enter a URL")
    else:
        prediction = predict_url(url_to_test)
        st.write("prediction:",prediction)
