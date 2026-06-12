const parallaxItems = Array.from(document.querySelectorAll("[data-parallax]"));
const revealItems = Array.from(document.querySelectorAll(".reveal"));

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
