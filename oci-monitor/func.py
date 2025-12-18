import io
import json
import logging
import os
from datetime import datetime
import oci
from fdk import response

def handler(ctx, data: io.BytesIO = None):
    try:
        # 1. Configuration / Environment Variables
        # These are set in the Function Configuration
        compartment_id = os.environ.get("COMPARTMENT_ID")
        instance_id = os.environ.get("INSTANCE_ID")
        
        if not compartment_id or not instance_id:
            raise ValueError("Missing COMPARTMENT_ID or INSTANCE_ID environment variables")

        # 2. Setup OCI Authentication (Resource Principal)
        signer = oci.auth.signers.get_resource_principals_signer()
        monitoring_client = oci.monitoring.MonitoringClient(config={}, signer=signer)
        compute_client = oci.core.ComputeClient(config={}, signer=signer)

        # 3. Calculate Traffic Logic
        now = datetime.utcnow()
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        logging.getLogger().info(f"Checking traffic from {start_of_month} to {now}")

        # BytesToIgw: Traffic flowing FROM VCN TO Internet Gateway (Egress)
        details = oci.monitoring.models.SummarizeMetricsDataDetails(
            namespace="oci_internet_gateway",
            query=f"BytesToIgw[1h].sum()", 
            start_time=start_of_month,
            end_time=now,
            resolution="1h"
        )

        result = monitoring_client.summarize_metrics_data(compartment_id, details)
        
        total_bytes = 0
        if result.data:
            for metric in result.data:
                for datapoint in metric.aggregated_datapoints:
                    total_bytes += datapoint.value
        
        logging.getLogger().info(f"Total BytesToIgw: {total_bytes}")

        # 4. Check Limit (9.5 TB precautionary limit for 10TB Free Tier)
        # 9.5 * 1024^4
        LIMIT_TB = 9.5
        limit_bytes = LIMIT_TB * 1024 * 1024 * 1024 * 1024
        
        status = "OK"
        if total_bytes > limit_bytes:
            logging.getLogger().critical(f"LIMIT EXCEEDED! Usage: {total_bytes} > Limit: {limit_bytes}. Stopping Instance.")
            
            # Check instance state first
            instance = compute_client.get_instance(instance_id).data
            if instance.lifecycle_state in ["RUNNING", "PROVISIONING", "STARTING"]:
                compute_client.instance_action(instance_id, "STOP")
                status = "STOPPED_INSTANCE"
            else:
                status = "ALREADY_NOT_RUNNING"
        else:
            logging.getLogger().info(f"Usage is within limits. {total_bytes / (1024*1024*1024*1024):.4f} TB used.")

        return response.Response(
            ctx, 
            response_data=json.dumps({
                "status": status, 
                "total_bytes": total_bytes,
                "limit_bytes": limit_bytes
            }),
            headers={"Content-Type": "application/json"}
        )

    except (Exception, ValueError) as ex:
        logging.getLogger().error(str(ex))
        return response.Response(
            ctx, 
            response_data=json.dumps({"error": str(ex)}),
            headers={"Content-Type": "application/json"},
            status_code=500
        )
