import { RSAA } from 'redux-api-middleware';

import { withAuth } from 'reducers/reducers.jsx';

export const LIST_FILES_REQUEST = '@@api/LIST_FILES_REQUEST';
export const LIST_FILES_SUCCESS = '@@api/LIST_FILES_SUCCESS';
export const LIST_FILES_FAILURE = '@@api/LIST_FILES_FAILURE';

export const LIST_COPY_JOBS_REQUEST = '@@api/LIST_COPY_JOBS_REQUEST';
export const LIST_COPY_JOBS_SUCCESS = '@@api/LIST_COPY_JOBS_SUCCESS';
export const LIST_COPY_JOBS_FAILURE = '@@api/LIST_COPY_JOBS_FAILURE';

export const RETRIEVE_COPY_JOB_REQUEST = '@@api/RETRIEVE_COPY_JOB_REQUEST';
export const RETRIEVE_COPY_JOB_SUCCESS = '@@api/RETRIEVE_COPY_JOB_SUCCESS';
export const RETRIEVE_COPY_JOB_FAILURE = '@@api/RETRIEVE_COPY_JOB_FAILURE';

export const CREATE_COPY_JOB_REQUEST = '@@api/CREATE_COPY_JOB_REQUEST';
export const CREATE_COPY_JOB_SUCCESS = '@@api/CREATE_COPY_JOB_SUCCESS';
export const CREATE_COPY_JOB_FAILURE = '@@api/CREATE_COPY_JOB_FAILURE';

export const STOP_COPY_JOB_REQUEST = '@@api/STOP_COPY_JOB_REQUEST';
export const STOP_COPY_JOB_SUCCESS = '@@api/STOP_COPY_JOB_SUCCESS';
export const STOP_COPY_JOB_FAILURE = '@@api/STOP_COPY_JOB_FAILURE';

export const LIST_CLOUD_CONNECTIONS_REQUEST = '@@api/LIST_CLOUD_CONNECTIONS_REQUEST';
export const LIST_CLOUD_CONNECTIONS_SUCCESS = '@@api/LIST_CLOUD_CONNECTIONS_SUCCESS';
export const LIST_CLOUD_CONNECTIONS_FAILURE = '@@api/LIST_CLOUD_CONNECTIONS_FAILURE';

export const CREATE_CLOUD_CONNECTION_REQUEST = '@@api/CREATE_CLOUD_CONNECTION_REQUEST';
export const CREATE_CLOUD_CONNECTION_SUCCESS = '@@api/CREATE_CLOUD_CONNECTION_SUCCESS';
export const CREATE_CLOUD_CONNECTION_FAILURE = '@@api/CREATE_CLOUD_CONNECTION_FAILURE';

export const UPDATE_CLOUD_CONNECTION_REQUEST = '@@api/UPDATE_CLOUD_CONNECTION_REQUEST';
export const UPDATE_CLOUD_CONNECTION_SUCCESS = '@@api/UPDATE_CLOUD_CONNECTION_SUCCESS';
export const UPDATE_CLOUD_CONNECTION_FAILURE = '@@api/UPDATE_CLOUD_CONNECTION_FAILURE';

export const DELETE_CLOUD_CONNECTION_REQUEST = '@@api/DELETE_CLOUD_CONNECTION_REQUEST';
export const DELETE_CLOUD_CONNECTION_SUCCESS = '@@api/DELETE_CLOUD_CONNECTION_SUCCESS';
export const DELETE_CLOUD_CONNECTION_FAILURE = '@@api/DELETE_CLOUD_CONNECTION_FAILURE';


export const listFiles = (side, data) => ({
    [RSAA]: {
        endpoint: '/api/system/files/',
        method: 'POST',
        body: JSON.stringify(data),
        headers: withAuth({ 'Content-Type': 'application/json' }),
        types: [
            {
                type: LIST_FILES_REQUEST,
                meta: {side, data},
            },
            {
                type: LIST_FILES_SUCCESS,
                meta: {side, data},
            },
            {
                type: LIST_FILES_FAILURE,
                meta: {side, data},
            },
        ]
    }
});


export const listCopyJobs = () => ({
    [RSAA]: {
        endpoint: `/api/copy-jobs/`,
        method: 'GET',
        headers: withAuth({ 'Content-Type': 'application/json' }),
        types: [ LIST_COPY_JOBS_REQUEST, LIST_COPY_JOBS_SUCCESS, LIST_COPY_JOBS_FAILURE ],
    }
});


export const retrieveCopyJob = (id) => ({
    [RSAA]: {
        endpoint: `/api/copy-jobs/${id}/`,
        method: 'GET',
        headers: withAuth({ 'Content-Type': 'application/json' }),
        types: [ RETRIEVE_COPY_JOB_REQUEST, RETRIEVE_COPY_JOB_SUCCESS, RETRIEVE_COPY_JOB_FAILURE ],
    }
});


export const createCopyJob = (data) => ({
    [RSAA]: {
        endpoint: `/api/copy-jobs/`, // TODO: Why is there a trailing slash here?
        method: 'POST',
        body: JSON.stringify(data),
        headers: withAuth({ 'Content-Type': 'application/json' }),
        types: [ CREATE_COPY_JOB_REQUEST, CREATE_COPY_JOB_SUCCESS, CREATE_COPY_JOB_FAILURE ],
    }
});

export const stopCopyJob = (id) => ({
    [RSAA]: {
        endpoint: `/api/copy-jobs/${id}/stop/`, // TODO: Why is there a trailing slash here?
        method: 'PUT',
        headers: withAuth({ 'Content-Type': 'application/json' }),
        types: [ STOP_COPY_JOB_REQUEST, STOP_COPY_JOB_SUCCESS, STOP_COPY_JOB_FAILURE ],
    }
});

export const listCloudConnections = (data) => ({
    [RSAA]: {
        endpoint: `/api/connections/`, // TODO: Why is there a trailing slash here?
        method: 'GET',
        headers: withAuth({ 'Content-Type': 'application/json' }),
        types: [ LIST_CLOUD_CONNECTIONS_REQUEST, LIST_CLOUD_CONNECTIONS_SUCCESS, LIST_CLOUD_CONNECTIONS_FAILURE ],
    }
});

export const createCloudConnection = (data) => {
    delete data.id;

    return {
        [RSAA]: {
            endpoint: `/api/connections/`, // TODO: Why is there a trailing slash here?
            method: 'POST',
            body: JSON.stringify(data),
            headers: withAuth({ 'Content-Type': 'application/json' }),
            types: [ CREATE_CLOUD_CONNECTION_REQUEST, CREATE_CLOUD_CONNECTION_SUCCESS, CREATE_CLOUD_CONNECTION_FAILURE ],
        }
    }
};

export const updateCloudConnection = (data) => {
    const id = data.id;
    delete data.id;

    return {
        [RSAA]: {
            endpoint: `/api/connections/${id}`, // TODO: Why is there a trailing slash here?
            method: 'PATCH',
            body: JSON.stringify(data),
            headers: withAuth({ 'Content-Type': 'application/json' }),
            types: [ UPDATE_CLOUD_CONNECTION_REQUEST, UPDATE_CLOUD_CONNECTION_SUCCESS, UPDATE_CLOUD_CONNECTION_FAILURE ],
        }
    }
};

export const deleteCloudConnection = (data) => {
    return {
        [RSAA]: {
            endpoint: `/api/connections/${data.id}`, // TODO: Why is there a trailing slash here?
            method: 'DELETE',
            headers: withAuth({ 'Content-Type': 'application/json' }),
            types: [ DELETE_CLOUD_CONNECTION_REQUEST, DELETE_CLOUD_CONNECTION_SUCCESS, DELETE_CLOUD_CONNECTION_FAILURE ],
        }
    }
};
