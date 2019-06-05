import React from 'react';


const headers = [
    "id",
    "type",
    "name",
    "bucket",
    "region",
    "access_key_id",
    "key_secret",
];


class Clouds extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const connectionRows = this.props.clouds.map((cloud, i) => {
            cloud['key_secret'] = '***'

            const items = headers.map((header, j) => {
                return (
                    <td key={j}>
                        {cloud[header]}
                    </td>
                );
            })

            return (
                <tr key={cloud.id}>
                    {items}
                </tr>
            );
        })



        return (
            <div className="container-fluid mt-4">
                <div className="row">
                    <div className="col-12">
                        <button
                            className="btn btn-success"
                            onClick={(event) => this.props.onShowNewConnectionDialog()}
                        >
                            New Connection
                        </button>
                    </div>
                    <div className="col-12 mt-4">
                        <table className="table text-center">
                            <thead>
                                <tr>
                                    {headers.map(header => <th key={header}>{header}</th>)}
                                </tr>
                            </thead>
                            <tbody>
                                {connectionRows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        );
    }

    componentDidMount() {
        this.props.onMount();
    }
}

Clouds.defaultProps = {
    clouds: [],
    onMount: () => {},
    onShowNewConnectionDialog: () => {},
}

import {connect} from 'react-redux';
import {showCloudConnectionDialog} from 'actions/dialogActions.jsx';
import {listCloudConnections} from 'actions/apiActions.jsx';

const mapStateToProps = state => ({
    clouds: state.api.clouds,
});

const mapDispatchToProps = dispatch => ({
    onMount: () => dispatch(listCloudConnections()),
    onShowNewConnectionDialog: () => dispatch(showCloudConnectionDialog()),
});

export default connect(mapStateToProps, mapDispatchToProps)(Clouds);