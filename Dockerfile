FROM python:3.9

RUN useradd -ms /bin/bash phishhook
USER phishhook
WORKDIR /home/phishhook
ADD requirements.txt .
RUN pip install --disable-pip-version-check --no-warn-script-location -r requirements.txt
RUN mkdir config
ADD run.sh .
ADD main.py .
ADD brand.py .
ADD config/brands.json config/
ADD README.md .
ENTRYPOINT ["./run.sh"]
