from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time, os

# Set up Selenium WebDriver
options = webdriver.ChromeOptions()
options.add_argument("--headless")  # Run Chrome in headless mode (no GUI)
options.add_argument("--disable-gpu")
options.add_argument("--window-size=1920,1080")
options.add_argument("--disable-blink-features=AutomationControlled")

# Initialize WebDriver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

# Open YouTube Live page
driver.get("https://www.youtube.com/live")

# Allow page to load
time.sleep(5)

# Output file to save live stream links
output_dir = "links/youtube.com/"
os.makedirs(output_dir, exist_ok=True)  # Ensure directory exists
output_file = os.path.join(output_dir, "links.txt")

# Function to scroll and extract links
def get_youtube_live_links(scrolls=50, wait_time=3):

    if os.path.exists(output_file):
        links = set(open(output_file).read().splitlines())
    else:
        links = set()

    for _ in range(scrolls):
        # Scroll to bottom
        driver.find_element(By.TAG_NAME, "body").send_keys(Keys.END)
        time.sleep(wait_time)  # Increased wait time to let YouTube load more videos

        # Extract live stream links
        elements = driver.find_elements(By.XPATH, '//a[contains(@href, "/live/")]')
        for elem in elements:
            link = elem.get_attribute("href")
            if link:
                if link not in links:
                    print(f"Found live stream: {link}")
                links.add(link)

        # Stop scrolling if no new videos are loading
        if len(links) >= 50:  # Adjust this threshold based on what you observe
            print("No more new videos loading. Stopping scroll.")
            break

    return list(links)

# Get live stream links
live_links = get_youtube_live_links(scrolls=100, wait_time=3)  # Scroll 50 times, wait 5 sec each

# Save links to a file

with open(output_file, "w") as f:
    for link in live_links:
        f.write(link + "\n")

# Close browser
driver.quit()

print(f"{len(live_links)} YouTube Live links saved to {output_file}")
