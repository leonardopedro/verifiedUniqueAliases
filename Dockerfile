# --- Builder Stage ---
FROM python:3.9-slim-bullseye AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Final Stage ---
FROM gcr.io/distroless/python3-debian11
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY app.py .
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]

#az container create     --resource-group LoginPaypal     --name confidential-paypal-app     --image ghcr.io/leonardopedro/temp-app:latest     --sku Confidential    --cce-policy "$FINAL_CCE_JSON" --assign-identity $RESOURCE_ID --os-type Linux --cpu 1 --memory 2