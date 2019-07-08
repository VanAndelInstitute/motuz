import time
import random
import functools
import logging
import re

from .. import celery
from ..models import CopyJob, CloudConnection
from ..application import db

from ..utils.rclone_connection import RcloneConnection


@celery.task(name='motuz.api.tasks.copy_job', bind=True)
def copy_job(self, task_id=None):
    start_time = time.time()

    copy_job = CopyJob.query.get(task_id)
    copy_job.progress_state = 'PROGRESS'
    db.session.commit()

    connection = RcloneConnection()
    connection.copy(
        src_data=copy_job.src_cloud,
        src_path=copy_job.src_resource,
        dst_data=copy_job.dst_cloud,
        dst_path=copy_job.dst_path,
        job_id=task_id,
    )

    while not connection.copy_finished(task_id):
        progress_current = connection.copy_percent(task_id)
        copy_job.progress_current = progress_current
        copy_job.progress_execution_time = int(time.time() - start_time)
        db.session.commit()

        self.update_state(state='PROGRESS', meta={
            'text': connection.copy_text(task_id),
            'error_text': connection.copy_error_text(task_id)
        })

        time.sleep(1)


    exitstatus = connection.copy_exitstatus(task_id)
    if exitstatus == -1:
        logging.error("Copy Job did not set its status")
        copy_job.progress_state = 'UNSET'
    elif exitstatus == 0:
        copy_job.progress_state = 'SUCCESS'
    else:
        copy_job.progress_state = 'FAILED'


    copy_job.progress_current = 100
    copy_job.progress_execution_time = int(time.time() - start_time)
    db.session.commit()

    return {
        'text': connection.copy_text(task_id),
        'error_text': connection.copy_error_text(task_id)
    }
