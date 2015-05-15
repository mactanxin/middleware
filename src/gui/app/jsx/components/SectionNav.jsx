// SECTION NAV
// ================
// Component for managing multiple views side by side

"use strict";

import React from "react";
import TWBS from "react-bootstrap";

import { Link } from "react-router";

const SectionNav = React.createClass(

  { propTypes: {
      views: React.PropTypes.array
    }

  , createNavItems: function ( item, index ) {
      return (
        <Link
          to = { item.route }
          key = { index }
          className = "btn btn-default"
          activeClassName = "active btn-info"
          role = "button"
          type = "button">
          { item.display }
        </Link>
      );
    }

  , render: function () {
      const viewNum = this.props.views.length;
      if ( viewNum > 1 ) {
        return (
          <TWBS.Grid fluid>
            <TWBS.Row className="text-center">
              <TWBS.ButtonGroup bsSize="large">
                { this.props.views.map( this.createNavItems ) }
              </TWBS.ButtonGroup>
            </TWBS.Row>
          </TWBS.Grid>
        );
      } else {
        console.warn(
          "A SectionNav is being called with " +
          viewNum === 1
            ? "only one view"
            : "no views"
        );
        return null;
      }
    }
  }

);

module.exports = SectionNav;
