FROM python:2-alpine3.6

RUN mkdir -p /opt/yair/

COPY . /opt/yair/

RUN pip install --no-cache-dir -r /opt/yair/requirements.txt

ENTRYPOINT ["/opt/yair/yair.py"]
CMD ""
