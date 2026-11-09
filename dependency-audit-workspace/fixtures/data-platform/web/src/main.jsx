import axios from "axios";
import React from "react";
import ReactDOM from "react-dom";

function App() {
  const [events, setEvents] = React.useState([]);
  React.useEffect(() => { axios.get("/api/events").then((r) => setEvents(r.data)); }, []);
  return React.createElement("ul", null, events.map((e) => React.createElement("li", { key: e.id }, e.name)));
}

ReactDOM.render(React.createElement(App), document.getElementById("root"));
