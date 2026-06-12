const parallaxItems = Array.from(document.querySelectorAll("[data-parallax]"));
const revealItems = Array.from(document.querySelectorAll(".reveal"));
const canvas = document.querySelector("#threatCanvas");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let particles = [];
let canvasWidth = 0;
let canvasHeight = 0;
let animationFrame = 0;

function updateParallax() {
  const scrollY = window.scrollY || 0;
  parallaxItems.forEach((item) => {
    const speed = Number(item.dataset.parallax || 0);
    item.style.transform = `translate3d(0, ${scrollY * speed}px, 0)`;
  });
}

const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
      }
    });
  },
  { threshold: 0.16 }
);

revealItems.forEach((item) => observer.observe(item));
window.addEventListener("scroll", updateParallax, { passive: true });
updateParallax();

function resizeCanvas() {
  if (!canvas) return;
  const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
  const rect = canvas.getBoundingClientRect();
  canvasWidth = rect.width;
  canvasHeight = rect.height;
  canvas.width = Math.max(1, Math.floor(canvasWidth * pixelRatio));
  canvas.height = Math.max(1, Math.floor(canvasHeight * pixelRatio));
  const context = canvas.getContext("2d");
  context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  const count = Math.max(42, Math.floor(canvasWidth / 18));
  particles = Array.from({ length: count }, (_, index) => ({
    x: (index * 89) % canvasWidth,
    y: (index * 137) % canvasHeight,
    vx: ((index % 5) - 2) * 0.16,
    vy: ((index % 7) - 3) * 0.12,
    size: 1 + (index % 4) * 0.38,
    pulse: (index % 11) / 11,
    risk: index % 13 === 0 ? "high" : index % 5 === 0 ? "watch" : "clear",
  }));
}

function particleColor(particle, alpha = 1) {
  if (particle.risk === "high") return `rgba(255, 106, 106, ${alpha})`;
  if (particle.risk === "watch") return `rgba(103, 214, 255, ${alpha})`;
  return `rgba(217, 255, 116, ${alpha})`;
}

function drawThreatScene(time = 0) {
  if (!canvas) return;
  const context = canvas.getContext("2d");
  context.clearRect(0, 0, canvasWidth, canvasHeight);
  context.fillStyle = "#05080c";
  context.fillRect(0, 0, canvasWidth, canvasHeight);

  particles.forEach((particle, index) => {
    if (!reducedMotion) {
      particle.x += particle.vx;
      particle.y += particle.vy;
      if (particle.x < -20) particle.x = canvasWidth + 20;
      if (particle.x > canvasWidth + 20) particle.x = -20;
      if (particle.y < -20) particle.y = canvasHeight + 20;
      if (particle.y > canvasHeight + 20) particle.y = -20;
    }

    for (let j = index + 1; j < particles.length; j += 1) {
      const other = particles[j];
      const dx = particle.x - other.x;
      const dy = particle.y - other.y;
      const distance = Math.hypot(dx, dy);
      if (distance < 132) {
        const alpha = (1 - distance / 132) * 0.18;
        context.strokeStyle = particleColor(particle, alpha);
        context.lineWidth = 1;
        context.beginPath();
        context.moveTo(particle.x, particle.y);
        context.lineTo(other.x, other.y);
        context.stroke();
      }
    }

    const pulse = 0.5 + Math.sin(time * 0.0016 + particle.pulse * 8) * 0.5;
    context.fillStyle = particleColor(particle, 0.45 + pulse * 0.35);
    context.beginPath();
    context.arc(particle.x, particle.y, particle.size + pulse * 1.8, 0, Math.PI * 2);
    context.fill();
  });

  context.strokeStyle = "rgba(238, 244, 247, 0.08)";
  context.lineWidth = 1;
  for (let y = 60; y < canvasHeight; y += 120) {
    context.beginPath();
    context.moveTo(0, y + Math.sin(time * 0.0008 + y) * 10);
    context.lineTo(canvasWidth, y + Math.cos(time * 0.0008 + y) * 10);
    context.stroke();
  }

  if (!reducedMotion) animationFrame = requestAnimationFrame(drawThreatScene);
}

if (canvas) {
  resizeCanvas();
  drawThreatScene();
  window.addEventListener("resize", () => {
    cancelAnimationFrame(animationFrame);
    resizeCanvas();
    drawThreatScene();
  });
}
