FROM python:3.11-slim-bookworm
WORKDIR /app
COPY requirement.txt requirement.txt
RUN pip3 install -r requirement.txt
COPY . .
CMD python3 M_IPLimiter.py
