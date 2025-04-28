var xValues = ["Under 15 år", "Under 30 år", "Under 45 år", "Under 60 år", "60 år eller mer"];
var prosentValues = [8.3, 66.7, 0, 25, 0];
var barColors = [
  "rgb(0, 98, 255)",
  "rgb(220, 3, 3)",
  "rgb(208, 182, 14)",
  "rgb(20, 134, 14)",
  "rgb(89, 4, 125)"
];

// Sjekk om Chart er tilgjengelig før du oppretter diagrammet
console.log(Chart);

new Chart("myChart", {
  type: "pie",  // Angi type som "pie" for sektordiagram
  data: {
    labels: xValues,
    datasets: [{
        backgroundColor: barColors,
        data: prosentValues
    }]
  },
  options: {
    title: {
      display: true,
      text: "Hvor gammel er du?"
    }
  }
});

var xValues = ["Alltid", "Ofte", "Av og til", "Litt", "Aldri", "Usikker"];
var prosentValues = [25, 50, 16.7, 0, 0, 8.3];
var barColors = [
  "rgb(0, 98, 255)",
  "rgb(220, 3, 3)",
  "rgb(208, 182, 14)",
  "rgb(20, 134, 14)",
  "rgb(89, 4, 125)",
  "rgb(5, 176, 206)"
];

// Sjekk om Chart er tilgjengelig før du oppretter diagrammet
console.log(Chart);

new Chart("myChart2", {
  type: "pie",  // Angi type som "pie" for sektordiagram
  data: {
    labels: xValues,
    datasets: [{
        backgroundColor: barColors,
        data: prosentValues
    }]
  },
  options: {
    title: {
      display: true,
      text: "Hvor gammel er du?"
    }
  }
});

var xValues = ["Ja", "Nei", "Usikker"];
var prosentValues = [81.8, 0, 18.2];
var barColors = [
  "rgb(0, 98, 255)",
  "rgb(220, 3, 3)",
  "rgb(208, 182, 14)"
];

// Sjekk om Chart er tilgjengelig før du oppretter diagrammet
console.log(Chart);

new Chart("myChart3", {
  type: "pie",  // Angi type som "pie" for sektordiagram
  data: {
    labels: xValues,
    datasets: [{
        backgroundColor: barColors,
        data: prosentValues
    }]
  },
  options: {
    title: {
      display: true,
      text: "Hvor gammel er du?"
    }
  }
});

var xValues = ["Ja", "Nei", "Usikker"];
var prosentValues = [66.7, 16.7, 16.7];
var barColors = [
  "rgb(0, 98, 255)",
  "rgb(220, 3, 3)",
  "rgb(208, 182, 14)"
];

// Sjekk om Chart er tilgjengelig før du oppretter diagrammet
console.log(Chart);

new Chart("myChart4", {
  type: "pie",  // Angi type som "pie" for sektordiagram
  data: {
    labels: xValues,
    datasets: [{
        backgroundColor: barColors,
        data: prosentValues
    }]
  },
});