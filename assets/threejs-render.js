import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

var canvasOfDesk = document.getElementById("rudeus-desk")

const scene = new THREE.Scene();
scene.add(new THREE.AxesHelper(0))
scene.position.y = -12

//const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.01, 1000);
const scW = canvasOfDesk.width
const scH = canvasOfDesk.height
console.log(scW, scH)
const scale = (scH * 0.005 + 4.8) * 5.5
const camera = new THREE.OrthographicCamera(
    -1.5*scale,
    1.5*scale,
    scale,
    -scale,
    0.01,
    50000
)
const initialCameraPosition = new THREE.Vector3(
    20 * Math.sin(0.2 * Math.PI),
    20,
    20 * Math.cos(0.2 * Math.PI)
)
const target = new THREE.Vector3(-0.5, 1.2, 0)

camera.position.copy(initialCameraPosition)
camera.lookAt(target)
//const initialCameraPosition = new THREE.Vector3(-5, 8, 18)

const renderer = new THREE.WebGLRenderer({ canvas: canvasOfDesk, alpha: true });
renderer.shadowMap.enabled = true
renderer.setPixelRatio(3 * window.devicePixelRatio)

const controls = new OrbitControls(camera, renderer.domElement)
controls.autoRotate = true
controls.target = target

const loader = new GLTFLoader();

const lightCandle = new THREE.SpotLight(0xffffff, 2000)
lightCandle.position.set(8, 40, -15)
scene.add(lightCandle)

const lightLaptop = new THREE.SpotLight(0xffffff, 2000)
lightLaptop.position.set(-10, 40, -15)
scene.add(lightLaptop)

const ambientLight = new THREE.AmbientLight(0xcccccc, Math.PI)
scene.add(ambientLight)

loader.load(
    '/assets/desk.glb',
    function(gltf) {
        var obj = gltf.scene
        scene.add(obj)
        obj.castShadow = true
        obj.receiveShadow = true
        obj.traverse(function(child) {
            if (child.isMesh) {
                child.castShadow = true
                child.receiveShadow = true
            }
            child.frustumCulled = false;

        })
    },
    (xhr) => {
        console.log((xhr.loaded / xhr.total) * 100 + '% loaded')
    },
    (error) => {
        console.log(error)
    }
)

window.addEventListener('resize', onWindowResize, false)
function onWindowResize() {
    camera.updateProjectionMatrix()
    render()
}

var frame = 1
function easeOutCirc(x) {
    return Math.sqrt(1 - Math.pow(x - 1, 4))
}
function animate() {

    frame = frame <= 100 ? frame + 1 : frame
    requestAnimationFrame(animate)

    if (frame <= 100) {
        var rotSpeed = -easeOutCirc(frame / 120) * Math.PI * 20
        const p = initialCameraPosition
        camera.position.y = p.y
        camera.position.x =
            p.x * Math.cos(rotSpeed) + p.z * Math.sin(rotSpeed)
        camera.position.z =
            p.z * Math.cos(rotSpeed) - p.x * Math.sin(rotSpeed)
        camera.lookAt(target)
    } else {
        controls.update()
    }


    render()

}

function render() {
    renderer.render(scene, camera)
}

animate()


